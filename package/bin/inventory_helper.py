import json
import time

import import_declare_test  # noqa: F401  (adds lib/ to sys.path)
from solnlib import conf_manager, log
from solnlib.modular_input import checkpointer
from solnlib.splunk_rest_client import SplunkRestClient
from splunklib import modularinput as smi

from shadowtrackr_common import ADDON_NAME, AUTH_HINT, CHECKPOINT_COLLECTION, build_client, logger_for_input, to_int
from shadowtrackr_lib.client import AuthError, ShadowTrackrError
from shadowtrackr_lib.inventory import InventoryCollector, KVStore, validate_interval
from shadowtrackr_lib.inventory_types import DEFAULT_TYPES, TYPES

SOURCETYPE = "shadowtrackr:inventory:summary"
PAGE = 10000  # rows per KV Store read
BATCH = 500  # rows per KV Store write (Splunk allows up to 1000)


class SplunkKVStore(KVStore):
    def __init__(self, session_key: str):
        self.service = SplunkRestClient(session_key, ADDON_NAME, owner="nobody")

    def _data(self, collection: str):
        return self.service.kvstore[collection].data

    def load(self, collection):
        data, rows, skip = self._data(collection), [], 0
        while True:
            page = data.query(limit=PAGE, skip=skip)
            rows.extend(page)
            if len(page) < PAGE:
                return rows
            skip += PAGE

    def save(self, collection, rows):
        data = self._data(collection)
        for i in range(0, len(rows), BATCH):
            data.batch_save(*rows[i : i + BATCH])

    def delete(self, collection, keys):
        data = self._data(collection)
        for i in range(0, len(keys), 100):
            data.delete(query=json.dumps({"$or": [{"_key": k} for k in keys[i : i + 100]]}))


def selected_types(value) -> list:
    if not value:
        return list(DEFAULT_TYPES)
    return [t.strip() for t in str(value).split("|") if t.strip() in TYPES]


def validate_input(definition: smi.ValidationDefinition):
    params = definition.parameters
    if params.get("interval") is not None:
        validate_interval(params.get("interval"))
    retention = params.get("retention_days")
    if retention is not None and not (1 <= to_int(retention, -1) <= 365):
        raise ValueError("retention_days must be a whole number between 1 and 365")
    if not selected_types(params.get("types")):
        raise ValueError("Select at least one inventory type")


def stream_events(inputs: smi.InputDefinition, event_writer: smi.EventWriter):
    session_key = inputs.metadata["session_key"]
    for input_name, input_item in inputs.inputs.items():
        normalized_input_name = input_name.split("/")[-1]
        logger = logger_for_input(normalized_input_name)
        try:
            logger.setLevel(
                conf_manager.get_log_level(
                    logger=logger, session_key=session_key, app_name=ADDON_NAME, conf_name="shadowtrackr_settings"
                )
            )
            log.modular_input_start(logger, normalized_input_name)
            account_name = input_item.get("account")
            index = input_item.get("index")
            ckpt = checkpointer.KVStoreCheckpointer(CHECKPOINT_COLLECTION, session_key, ADDON_NAME)
            ckpt_key = f"inventory_{normalized_input_name}"

            collector = InventoryCollector(
                client=build_client(session_key, account_name),
                kv=SplunkKVStore(session_key),
                load_state=lambda: ckpt.get(ckpt_key),
                save_state=lambda state: ckpt.update(ckpt_key, state),
                logger=logger,
                types=selected_types(input_item.get("types")),
                retention_days=to_int(input_item.get("retention_days"), 30),
            )
            started = time.time()
            summaries = collector.run()
            for summary in summaries:
                event_writer.write_event(
                    smi.Event(
                        data=json.dumps(dict(summary, input=normalized_input_name), ensure_ascii=False),
                        time=f"{started:.3f}",
                        index=index,
                        sourcetype=SOURCETYPE,
                    )
                )
            log.events_ingested(logger, input_name, SOURCETYPE, len(summaries), index, account=account_name)
            log.modular_input_end(logger, normalized_input_name)
        except AuthError as e:
            log.log_exception(
                logger,
                e,
                "Authentication Error",
                msg_before="ShadowTrackr rejected the API key for account "
                f"'{input_item.get('account')}'. {AUTH_HINT}: ",
            )
        except ShadowTrackrError as e:
            log.log_exception(logger, e, "API Error", msg_before="ShadowTrackr API request failed: ")
        except Exception as e:
            log.log_exception(logger, e, "Unknown Error", msg_before="Unexpected error while syncing inventory: ")
