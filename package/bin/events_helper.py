import json
import logging
import time
from datetime import timedelta

import import_declare_test  # noqa: F401  (adds lib/ to sys.path)
from solnlib import conf_manager, log
from solnlib.modular_input import checkpointer
from solnlib.splunk_rest_client import SplunkRestClient
from splunklib import modularinput as smi

from shadowtrackr_lib import event_types
from shadowtrackr_lib.client import APIError, AuthError, ShadowTrackrClient, ShadowTrackrError, build_proxy_url
from shadowtrackr_lib.events import EventCollector

ADDON_NAME = "shadowtrackr"
SOURCETYPE = "shadowtrackr:events"
CHECKPOINT_COLLECTION = "shadowtrackr_checkpoints"
EVENT_TYPE_COLLECTION = "shadowtrackr_event_type_catalog"
EVENT_TYPE_CHECKPOINT = "event_type_catalog"
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


def _int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def build_client(session_key: str, account_name: str) -> ShadowTrackrClient:
    account = get_account(session_key, account_name)
    settings = get_settings(session_key)
    kwargs = {
        "api_key": account.get("api_key"),
        "timeout": _int(settings["advanced"].get("request_timeout"), DEFAULT_TIMEOUT),
        "proxy_url": build_proxy_url(settings["proxy"]),
    }
    if account.get("base_url"):
        kwargs["base_url"] = account["base_url"]
    return ShadowTrackrClient(**kwargs)


def refresh_event_type_catalog(client, session_key, ckpt, logger) -> None:
    """Refresh the event type lookup from /event_types once a day."""
    state = ckpt.get(EVENT_TYPE_CHECKPOINT) or {}
    if time.time() - float(state.get("refreshed", 0)) < event_types.REFRESH_INTERVAL_SECONDS:
        return
    try:
        records = event_types.to_records(client.event_types())
    except APIError as e:
        # Older API versions have no /event_types; the curated lookup still works.
        logger.info("Event type catalogue not available: %s", e)
        records = []
    if records:
        data = SplunkRestClient(session_key, ADDON_NAME, owner="nobody").kvstore[EVENT_TYPE_COLLECTION].data
        for i in range(0, len(records), 500):
            data.batch_save(*records[i : i + 500])
        logger.info("Refreshed %d event types", len(records))
    ckpt.update(EVENT_TYPE_CHECKPOINT, {"refreshed": time.time()})


def validate_input(definition: smi.ValidationDefinition):
    params = definition.parameters
    for field, low, high in (("backfill_days", 0, 90), ("overlap_minutes", 0, 1440)):
        value = params.get(field)
        if value is not None and not (low <= _int(value, -1) <= high):
            raise ValueError(f"{field} must be a whole number between {low} and {high}")


def stream_events(inputs: smi.InputDefinition, event_writer: smi.EventWriter):
    session_key = inputs.metadata["session_key"]
    for input_name, input_item in inputs.inputs.items():
        normalized_input_name = input_name.split("/")[-1]
        logger = logger_for_input(normalized_input_name)
        try:
            log_level = conf_manager.get_log_level(
                logger=logger,
                session_key=session_key,
                app_name=ADDON_NAME,
                conf_name="shadowtrackr_settings",
            )
            logger.setLevel(log_level)
            log.modular_input_start(logger, normalized_input_name)

            account_name = input_item.get("account")
            index = input_item.get("index")
            client = build_client(session_key, account_name)
            ckpt = checkpointer.KVStoreCheckpointer(CHECKPOINT_COLLECTION, session_key, ADDON_NAME)
            ckpt_key = f"events_{normalized_input_name}"

            def write(record, timestamp):
                event_writer.write_event(
                    smi.Event(
                        data=json.dumps(record, ensure_ascii=False, default=str),
                        time=f"{timestamp:.3f}" if timestamp is not None else None,
                        index=index,
                        sourcetype=SOURCETYPE,
                    )
                )

            collector = EventCollector(
                client=client,
                load_checkpoint=lambda: ckpt.get(ckpt_key),
                save_checkpoint=lambda state: ckpt.update(ckpt_key, state),
                write_event=write,
                logger=logger,
                backfill=timedelta(days=_int(input_item.get("backfill_days"), 7)),
                overlap=timedelta(minutes=_int(input_item.get("overlap_minutes"), 15)),
            )
            count = collector.run()
            log.events_ingested(logger, input_name, SOURCETYPE, count, index, account=account_name)
            refresh_event_type_catalog(client, session_key, ckpt, logger)
            log.modular_input_end(logger, normalized_input_name)
        except AuthError as e:
            log.log_exception(
                logger,
                e,
                "Authentication Error",
                msg_before="ShadowTrackr rejected the API key for account "
                f"'{input_item.get('account')}'. Check the key and that API access is enabled: ",
            )
        except ShadowTrackrError as e:
            log.log_exception(logger, e, "API Error", msg_before="ShadowTrackr API request failed: ")
        except Exception as e:
            log.log_exception(logger, e, "Unknown Error", msg_before="Unexpected error while collecting events: ")
