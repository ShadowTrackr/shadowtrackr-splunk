"""| stenrich field=<field> [type=auto|ip|domain] [prefix=st_]

Streaming command that adds ShadowTrackr context (st_* fields) to any
search, from the inventory KV Store lookups. Makes no API calls, so every
user who can read the lookups can run it. Runs on the search head, where the
KV Store is.
"""

import json
import sys

import import_declare_test  # noqa: F401  (adds lib/ to sys.path)
from splunklib.searchcommands import Configuration, Option, StreamingCommand, dispatch, validators

from shadowtrackr_common import search_service
from shadowtrackr_lib.enrich import KINDS, Enricher, apply, normalize

BUFFER = 1000  # records collected before one round of lookups


@Configuration(distributed=False)
class StEnrichCommand(StreamingCommand):
    field = Option(doc="Field holding an IP, hostname or URL", require=True, validate=validators.Fieldname())
    type = Option(doc="auto (default), ip or domain", require=False, default="auto", validate=validators.Set(*KINDS))
    prefix = Option(doc="Prefix of the added fields (default st_)", require=False, default="st_")

    def prepare(self):
        self._missing = set()
        self._service = search_service(self._metadata.searchinfo)
        self._enricher = Enricher(self._lookup)

    def _lookup(self, collection, field, values):
        try:
            data = self._service.kvstore[collection].data
            return data.query(query=json.dumps({field: {"$in": list(values)}}))
        except KeyError:
            self._warn_once(collection, "Lookup {} not found. Set up the ShadowTrackr Inventory input.".format(
                collection))
        except Exception as e:  # KV Store down or not readable: enrich what we can
            self._warn_once(collection, "Cannot read lookup {}: {}".format(collection, e))
        return []

    def _warn_once(self, collection, message):
        if collection not in self._missing:
            self._missing.add(collection)
            self.write_warning(message)

    def stream(self, records):
        buffer = []
        for record in records:
            buffer.append(record)
            if len(buffer) >= BUFFER:
                yield from self._flush(buffer)
                buffer = []
        yield from self._flush(buffer)

    def _flush(self, records):
        keys = [normalize(r.get(self.field), self.type) for r in records]
        context = self._enricher.enrich(k for k in keys if k)
        for record, key in zip(records, keys):
            yield apply(record, context.get(key) if key else None, self.prefix)


dispatch(StEnrichCommand, sys.argv, sys.stdin, sys.stdout, __name__)
