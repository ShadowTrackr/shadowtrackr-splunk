import json
import time
from datetime import timedelta

import import_declare_test  # noqa: F401  (adds lib/ to sys.path)
from solnlib import conf_manager, log
from solnlib.modular_input import checkpointer
from solnlib.splunk_rest_client import SplunkRestClient
from splunklib import modularinput as smi

from shadowtrackr_common import ADDON_NAME, CHECKPOINT_COLLECTION, build_client, logger_for_input, to_int
from shadowtrackr_lib import event_types
from shadowtrackr_lib.client import APIError, AuthError, ShadowTrackrError
from shadowtrackr_lib.events import EventCollector

SOURCETYPE = "shadowtrackr:events"
EVENT_TYPE_COLLECTION = "shadowtrackr_event_type_catalog"
EVENT_TYPE_CHECKPOINT = "event_type_catalog"


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
        if value is not None and not (low <= to_int(value, -1) <= high):
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
                backfill=timedelta(days=to_int(input_item.get("backfill_days"), 7)),
                overlap=timedelta(minutes=to_int(input_item.get("overlap_minutes"), 15)),
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
