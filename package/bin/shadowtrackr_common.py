"""Splunk-side helpers shared by the modular inputs: logging, settings, API client."""

import logging

import import_declare_test  # noqa: F401  (adds lib/ to sys.path)
from solnlib import conf_manager, log

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


def build_client(session_key: str, account_name: str) -> ShadowTrackrClient:
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
