"""Minimal client for the ShadowTrackr v4 API.

Every endpoint is a POST with a JSON body and a bearer token. Responses use
the envelope {"results": ..., "error": "...", "data": [...]}. Note that the
API reports an invalid key with HTTP 200 and a non-empty "error" field, so
the envelope has to be checked as well as the status code.
"""

import json
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote

import urllib3

USER_AGENT = "shadowtrackr-splunk"
DEFAULT_BASE_URL = "https://api.shadowtrackr.com/api/v4"

# Never wait longer than this for a Retry-After header within one run.
MAX_RETRY_AFTER = 300

# Errors in the envelope that mean the key or subscription is the problem.
# Retrying these will not help.
_AUTH_ERROR_MARKERS = ("api key", "unauthorized", "api access", "subscription")


class ShadowTrackrError(Exception):
    """Base class for API errors."""


class AuthError(ShadowTrackrError):
    """The API key is missing, wrong, revoked or lacks API access."""


class TransientError(ShadowTrackrError):
    """A temporary failure (network, timeout, 429 or 5xx) worth retrying."""

    def __init__(self, message: str, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after


class APIError(ShadowTrackrError):
    """Any other error reported by the API or an unexpected response."""


def _int_or_none(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    """Parse a Retry-After header given in seconds. HTTP dates are ignored."""
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    return seconds if seconds >= 0 else None


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

    def request(self, endpoint: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """POST to an endpoint and return the whole response envelope.

        Transient failures are retried with exponential backoff, or after the
        server's Retry-After delay when it sends one. Other errors raise
        immediately.
        """
        attempt = 0
        while True:
            try:
                return self._post_once(endpoint, body or {})
            except TransientError as e:
                attempt += 1
                if attempt > self.max_retries:
                    raise
                delay = self.backoff * (2 ** (attempt - 1))
                if e.retry_after is not None:
                    delay = min(max(delay, e.retry_after), MAX_RETRY_AFTER)
                self._sleep(delay)

    def post(self, endpoint: str, body: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """POST to an endpoint and return the "data" list."""
        data = self.request(endpoint, body).get("data")
        if data is None:
            return []
        if not isinstance(data, list):
            raise APIError("Unexpected 'data' type from {}: {}".format(endpoint, type(data).__name__))
        return data

    def _post_once(self, endpoint: str, body: Dict[str, Any]) -> Dict[str, Any]:
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
            raise TransientError(
                "HTTP {} from {}".format(status, endpoint),
                retry_after=_parse_retry_after(resp.headers.get("Retry-After")),
            )

        payload = self._decode(resp.data)
        error = payload.get("error") if isinstance(payload, dict) else None

        # 401: no, unknown or revoked key. 403: API access not enabled, or an
        # organization outside the group. Both need the user to fix the setup.
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
            # Older API versions report a bad key with HTTP 200.
            if any(m in error.lower() for m in _AUTH_ERROR_MARKERS):
                raise AuthError(error)
            raise APIError("{}: {} (HTTP {})".format(endpoint, error, status))
        if status >= 400:
            raise APIError("HTTP {} from {}".format(status, endpoint))
        return payload

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

    def latest_id(self) -> Optional[int]:
        """Highest event id the key can see (envelope latest_id), or None.

        None means the API version has no event ids.
        """
        envelope = self.request("events", {"limit": 1})
        return _int_or_none(envelope.get("latest_id"))

    def events_since(self, since_id: int, limit: int) -> Tuple[List[Dict[str, Any]], Optional[int]]:
        """Return events with id > since_id, ascending by id, and next_since_id.

        next_since_id is None when the API does not support id paging.
        """
        envelope = self.request("events", {"since_id": since_id, "limit": limit})
        data = envelope.get("data") or []
        if not isinstance(data, list):
            raise APIError("Unexpected 'data' type from events: {}".format(type(data).__name__))
        return data, _int_or_none(envelope.get("next_since_id"))

    def event_types(self) -> List[Dict[str, Any]]:
        """Return the event type catalogue (eventid, name, category, ...)."""
        return self.post("event_types", {})
