"""Minimal client for the ShadowTrackr v4 API.

Every endpoint is a POST with a JSON body and a bearer token. Responses use
the envelope {"results": ..., "error": "...", "data": [...]}. Note that the
API reports an invalid key with HTTP 200 and a non-empty "error" field, so
the envelope has to be checked as well as the status code.
"""

import json
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote

import urllib3

USER_AGENT = "shadowtrackr-splunk"
DEFAULT_BASE_URL = "https://api.shadowtrackr.com/api/v4"

# Errors in the envelope that mean the key or subscription is the problem.
# Retrying these will not help.
_AUTH_ERROR_MARKERS = ("api key", "unauthorized", "api access", "subscription")


class ShadowTrackrError(Exception):
    """Base class for API errors."""


class AuthError(ShadowTrackrError):
    """The API key is missing, wrong, revoked or lacks API access."""


class TransientError(ShadowTrackrError):
    """A temporary failure (network, timeout, 429 or 5xx) worth retrying."""


class APIError(ShadowTrackrError):
    """Any other error reported by the API or an unexpected response."""


def build_proxy_url(settings: Dict[str, Any]) -> Optional[str]:
    """Build a proxy URL from the UCC proxy tab fields, or None if disabled."""
    if str(settings.get("proxy_enabled", "")).lower() not in ("1", "true"):
        return None
    host = settings.get("proxy_url")
    if not host:
        return None
    scheme = settings.get("proxy_type") or "http"
    if scheme == "socks5" and str(settings.get("proxy_rdns", "")).lower() in ("1", "true"):
        scheme = "socks5h"
    elif scheme == "socks4" and str(settings.get("proxy_rdns", "")).lower() in ("1", "true"):
        scheme = "socks4a"
    auth = ""
    if settings.get("proxy_username"):
        auth = quote(settings["proxy_username"], safe="")
        if settings.get("proxy_password"):
            auth += ":" + quote(settings["proxy_password"], safe="")
        auth += "@"
    port = settings.get("proxy_port")
    return "{}://{}{}{}".format(scheme, auth, host, ":{}".format(port) if port else "")


def _pool_manager(proxy_url: Optional[str]) -> urllib3.PoolManager:
    if not proxy_url:
        return urllib3.PoolManager()
    if proxy_url.startswith("socks"):
        from urllib3.contrib.socks import SOCKSProxyManager

        return SOCKSProxyManager(proxy_url)
    return urllib3.ProxyManager(proxy_url)


class ShadowTrackrClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 60,
        proxy_url: Optional[str] = None,
        max_retries: int = 3,
        backoff: float = 2.0,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if not api_key:
            raise AuthError("No API key configured")
        self._api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff = backoff
        self._sleep = sleep
        self._http = _pool_manager(proxy_url)

    def post(self, endpoint: str, body: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """POST to an endpoint and return the "data" list.

        Transient failures are retried with exponential backoff. Other errors
        raise immediately.
        """
        attempt = 0
        while True:
            try:
                return self._post_once(endpoint, body or {})
            except TransientError:
                attempt += 1
                if attempt > self.max_retries:
                    raise
                self._sleep(self.backoff * (2 ** (attempt - 1)))

    def _post_once(self, endpoint: str, body: Dict[str, Any]) -> List[Dict[str, Any]]:
        url = "{}/{}".format(self.base_url, endpoint)
        try:
            resp = self._http.request(
                "POST",
                url,
                body=json.dumps(body).encode("utf-8"),
                headers={
                    "Authorization": "Bearer " + self._api_key,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": USER_AGENT,
                },
                timeout=urllib3.Timeout(connect=min(self.timeout, 30), read=self.timeout),
                retries=False,
                redirect=False,
            )
        except urllib3.exceptions.HTTPError as e:
            # Covers timeouts, connection and proxy errors. The message never
            # contains the request headers, so the key is not leaked.
            raise TransientError("Request to {} failed: {}".format(endpoint, e.__class__.__name__)) from None

        status = resp.status
        if status == 429 or status >= 500:
            raise TransientError("HTTP {} from {}".format(status, endpoint))

        payload = self._decode(resp.data)
        error = payload.get("error") if isinstance(payload, dict) else None

        if status in (401, 403):
            raise AuthError(error or "HTTP {} from {}".format(status, endpoint))
        if payload is None or not isinstance(payload, dict):
            content_type = resp.headers.get("Content-Type", "unknown")
            raise APIError(
                "Unexpected response from {} (HTTP {}, {}). Check the API base URL.".format(
                    endpoint, status, content_type.split(";")[0]
                )
            )
        if error:
            if any(m in error.lower() for m in _AUTH_ERROR_MARKERS):
                raise AuthError(error)
            raise APIError("{}: {}".format(endpoint, error))
        if status >= 400:
            raise APIError("HTTP {} from {}".format(status, endpoint))

        data = payload.get("data")
        if data is None:
            return []
        if not isinstance(data, list):
            raise APIError("Unexpected 'data' type from {}: {}".format(endpoint, type(data).__name__))
        return data

    @staticmethod
    def _decode(raw: bytes) -> Any:
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None

    def events(self, start: str, stop: str) -> List[Dict[str, Any]]:
        """Return all events with start <= timestamp <= stop (UTC, inclusive).

        With both bounds set the API returns the whole window (no 1000 cap),
        grouped by event type rather than sorted by time. Callers sort.
        """
        return self.post("events", {"start": start, "stop": stop})
