#!/usr/bin/env python3
"""Fill the dev Splunk with synthetic firewall, proxy/WAF, auth and IDS logs for Asset 360.

Development only; nothing here ships in the app. It:
  * creates the index "devlogs" (if missing)
  * creates CIM eventtypes and tags for the devlogs:* sourcetypes in the
    search app, shared globally, so the Asset 360 macros (CIM tags) find them
  * picks assets from the shadowtrackr_hosts lookup (run the inventory input
    first) and sends a few days of key=value events via HEC: traffic to and
    from those assets, web requests, logins and IDS alerts, plus noise for
    unrelated addresses

Usage (Splunk in Docker, credentials from .env):
  python3 -I tools/gen_dev_logs.py [--days 7] [--assets 8] [--events 3000]
"""

import argparse
import base64
import json
import os
import random
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MGMT = "https://localhost:8089"
HEC = "https://localhost:8088/services/collector/event"
INDEX = "devlogs"
CTX = ssl._create_unverified_context()

EVENTTYPES = {
    "devlogs_network": ("sourcetype=devlogs:firewall", ["network", "communicate"]),
    "devlogs_web": ("sourcetype=devlogs:web", ["web", "proxy"]),
    "devlogs_auth": ("sourcetype=devlogs:auth", ["authentication"]),
    "devlogs_ids": ("sourcetype=devlogs:ids", ["ids", "attack"]),
}

SIGNATURES = [("ET SCAN Nmap Scripting Engine User-Agent", "medium"),
              ("ET EXPLOIT Possible OpenSSH regreSSHion attempt", "high"),
              ("SQL injection attempt in query string", "high"),
              ("ET SCAN Suspicious inbound to MSSQL port 1433", "low"),
              ("Path traversal attempt (../)", "medium")]
PATHS = ["/", "/login", "/wp-login.php", "/api/v1/status", "/.env", "/admin", "/index.php?id=1%27%20OR%201=1"]
USERS = ["alice", "bob", "svc_backup", "root", "admin", "deploy"]


def load_env():
    env = {}
    with open(os.path.join(ROOT, ".env"), encoding="utf-8") as f:
        for line in f:
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.rstrip("\n").split("=", 1)
                env[key.strip()] = value.strip()
    return env


def rest(env, method, path, data=None):
    auth = base64.b64encode(("admin:" + env["SPLUNK_PASSWORD"]).encode()).decode()
    body = urllib.parse.urlencode(dict(data or {}, output_mode="json"), doseq=True).encode() if method == "POST" \
        else None
    url = MGMT + path + ("" if method == "POST" else ("&" if "?" in path else "?") + "output_mode=json")
    req = urllib.request.Request(url, data=body, method=method, headers={"Authorization": "Basic " + auth})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=60) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, None


def setup(env):
    status, _ = rest(env, "GET", "/services/data/indexes/" + INDEX)
    if status == 404:
        rest(env, "POST", "/services/data/indexes", {"name": INDEX})
        print("created index", INDEX)
    for name, (search, tags) in EVENTTYPES.items():
        status, _ = rest(env, "GET", "/servicesNS/nobody/search/saved/eventtypes/" + name)
        if status == 404:
            rest(env, "POST", "/servicesNS/nobody/search/saved/eventtypes", {"name": name, "search": search})
        rest(env, "POST", "/servicesNS/nobody/search/saved/eventtypes/{}/acl".format(name),
             {"sharing": "global", "owner": "nobody", "perms.read": "*", "perms.write": "admin"})
        stanza = "eventtype=" + name
        values = {tag: "enabled" for tag in tags}
        status, _ = rest(env, "POST", "/servicesNS/nobody/search/configs/conf-tags/" + urllib.parse.quote(stanza, ""),
                         values)
        if status == 404:
            rest(env, "POST", "/servicesNS/nobody/search/configs/conf-tags", dict(values, name=stanza))
        rest(env, "POST", "/servicesNS/nobody/search/configs/conf-tags/{}/acl".format(urllib.parse.quote(stanza, "")),
             {"sharing": "global", "owner": "nobody", "perms.read": "*", "perms.write": "admin"})
    print("eventtypes and tags ready:", ", ".join(EVENTTYPES))


def assets(env, count):
    query = urllib.parse.quote(json.dumps({"st_present": 1}))
    status, rows = rest(env, "GET", "/servicesNS/nobody/shadowtrackr/storage/collections/data/shadowtrackr_hosts"
                                    "?limit=200&query=" + query)
    if status != 200 or not rows:
        raise SystemExit("No rows in shadowtrackr_hosts. Run the ShadowTrackr Inventory input first.")
    random.shuffle(rows)
    return [{"ip": r["ip"], "names": r.get("hostnames") or [], "ports": r.get("tcp_ports") or [443]}
            for r in rows[:count] if r.get("ip")]


def rand_ip(internal=False):
    if internal:
        return "10.{}.{}.{}".format(random.randint(0, 3), random.randint(0, 255), random.randint(1, 254))
    return "{}.{}.{}.{}".format(random.choice([45, 80, 91, 185, 193, 203]), random.randint(0, 255),
                                random.randint(0, 255), random.randint(1, 254))


def kv(**fields):
    return " ".join('{}="{}"'.format(k, v) for k, v in fields.items())


def event(targets, now, days):
    t = now - random.random() * days * 86400
    a = random.choice(targets) if random.random() < 0.8 else {"ip": rand_ip(), "names": ["other.example.org"],
                                                                "ports": [443]}
    name = random.choice(a["names"]) if a["names"] else a["ip"]
    kind = random.choices(["firewall", "web", "auth", "ids"], weights=[50, 25, 15, 10])[0]
    if kind == "firewall":
        inbound = random.random() < 0.7
        port = random.choice(a["ports"]) if random.random() < 0.8 else random.choice([22, 23, 3389, 445, 1433])
        raw = kv(src_ip=rand_ip() if inbound else rand_ip(internal=True), dest_ip=a["ip"], dest_port=port,
                 transport="tcp", action=random.choice(["allowed"] * 4 + ["blocked"]), bytes=random.randint(60, 90000))
    elif kind == "web":
        raw = kv(src=rand_ip(internal=random.random() < 0.5), dest=name, dest_ip=a["ip"],
                 http_method=random.choice(["GET"] * 5 + ["POST"]), url="https://{}{}".format(name, random.choice(PATHS)),
                 status=random.choice([200, 200, 200, 301, 403, 404, 500]),
                 action=random.choice(["allowed"] * 5 + ["blocked"]))
    elif kind == "auth":
        raw = kv(user=random.choice(USERS), src=rand_ip(), dest=name, dest_ip=a["ip"],
                 app=random.choice(["sshd", "vpn", "owa"]), action=random.choice(["success", "failure", "failure"]))
    else:
        signature, severity = random.choice(SIGNATURES)
        raw = kv(signature=signature, severity=severity, src=rand_ip(), dest_ip=a["ip"], dest=name,
                 action=random.choice(["allowed", "blocked"]))
    return {"time": round(t, 3), "index": INDEX, "sourcetype": "devlogs:" + kind, "host": "devlogs", "event": raw}


def send(env, events):
    for i in range(0, len(events), 500):
        body = "\n".join(json.dumps(e) for e in events[i:i + 500]).encode()
        req = urllib.request.Request(HEC, data=body, headers={"Authorization": "Splunk " + env["SPLUNK_HEC_TOKEN"]})
        with urllib.request.urlopen(req, context=CTX, timeout=60) as resp:
            resp.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--assets", type=int, default=8)
    parser.add_argument("--events", type=int, default=3000)
    args = parser.parse_args()

    env = load_env()
    setup(env)
    targets = assets(env, args.assets)
    now = time.time()
    events = [event(targets, now, args.days) for _ in range(args.events)]
    send(env, events)
    print("sent {} events to index={} for {} assets, e.g. {}".format(
        len(events), INDEX, len(targets), ", ".join(t["names"][0] if t["names"] else t["ip"] for t in targets[:3])))


if __name__ == "__main__":
    main()
