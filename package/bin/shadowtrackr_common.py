"""Splunk-side helpers shared by the modular inputs: logging, settings, API client."""

import logging

import import_declare_test  # noqa: F401  (adds lib/ to sys.path)
from solnlib import conf_manager, log
from urllib.parse import urlsplit

from splunklib.client import Service

from shadowtrackr_lib.client import ShadowTrackrClient, build_proxy_url

ADDON_NAME = "shadowtrackr"
CHECKPOINT_COLLECTION = "shadowtrackr_checkpoints"
DEFAULT_TIMEOUT = 60


def logger_for_input(input_name: str) -> logging.Logger:
    return log.Logs().get_logger(f"{ADDON_NAME.lower()}_{input_name}")


def _conf(session_key: str, conf_name: str):
    cfm = conf_manager.ConfManager(
        session_key,
        ADDON_NAME,
        realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-{conf_name}",
    )
    return cfm.get_conf(conf_name)


def get_account(session_key: str, account_name: str) -> dict:
    return _conf(session_key, "shadowtrackr_account").get(account_name)


def get_settings(session_key: str) -> dict:
    settings_conf = _conf(session_key, "shadowtrackr_settings")
    settings = {}
    for stanza in ("proxy", "advanced"):
        try:
            settings[stanza] = settings_conf.get(stanza) or {}
        except conf_manager.ConfStanzaNotExistException:
            settings[stanza] = {}
    return settings


def to_int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def build_client(session_key: str, account_name: str, account: dict = None) -> ShadowTrackrClient:
    if account is None:
        account = get_account(session_key, account_name)
    settings = get_settings(session_key)
    kwargs = {
        "api_key": account.get("api_key"),
        "timeout": to_int(settings["advanced"].get("request_timeout"), DEFAULT_TIMEOUT),
        "proxy_url": build_proxy_url(settings["proxy"]),
    }
    if account.get("base_url"):
        kwargs["base_url"] = account["base_url"]
    return ShadowTrackrClient(**kwargs)


def search_service(searchinfo) -> Service:
    """A splunkd connection for a search command, in this app's namespace.

    Uses the search's own session, so it works for every role. (solnlib's
    SplunkRestClient first reads the server's SSL settings, which only admins
    may do.)
    """
    uri = urlsplit(searchinfo.splunkd_uri, allow_fragments=False)
    return Service(scheme=uri.scheme, host=uri.hostname, port=uri.port, token=searchinfo.session_key,
                   owner="nobody", app=ADDON_NAME)


def list_account_names(service: Service) -> list:
    """Configured account names. Reads only the stanza names, no credentials."""
    try:
        conf = service.confs["shadowtrackr_account"]
    except KeyError:
        return []
    return sorted(stanza.name for stanza in conf.list() if stanza.name != "default")


class CredentialAccessError(Exception):
    """The current user may not read the encrypted API key."""


def build_client_for_search(session_key: str, account_name: str) -> ShadowTrackrClient:
    """build_client() for search commands, with a clear error when the user may not read the key.

    Reading the encrypted key needs the list_storage_passwords capability
    (admin and sc_admin have it).
    """
    try:
        account = get_account(session_key, account_name)
    except Exception as e:
        raise CredentialAccessError(
            "Cannot read the API key of ShadowTrackr account '{}' ({}). Running | shadowtrackr needs the "
            "list_storage_passwords capability, which admin has. Ask your Splunk admin.".format(
                account_name, e.__class__.__name__)
        ) from None
    if not account or not account.get("api_key") or account.get("api_key") == "********":
        raise CredentialAccessError(
            "Cannot read the API key of ShadowTrackr account '{}'. Running | shadowtrackr needs the "
            "list_storage_passwords capability, which admin has. Ask your Splunk admin.".format(account_name)
        )
    return build_client(session_key, account_name, account)
