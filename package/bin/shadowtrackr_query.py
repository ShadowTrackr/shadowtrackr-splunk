"""| shadowtrackr query="..." [account=<name>] [max_results=10000]

Generating command that runs a live query against the ShadowTrackr v4 API
and returns the rows as results. Runs on the search head only.
"""

import sys

import import_declare_test  # noqa: F401  (adds lib/ to sys.path)
from splunklib.searchcommands import Configuration, GeneratingCommand, Option, dispatch, validators

from shadowtrackr_common import AUTH_HINT, CredentialAccessError, build_client_for_search, list_account_names, search_service
from shadowtrackr_lib.client import AuthError, ShadowTrackrError
from shadowtrackr_lib.query import DEFAULT_MAX_RESULTS, choose_account, run_query


@Configuration(type="reporting")
class ShadowTrackrCommand(GeneratingCommand):
    query = Option(
        doc="Query in the ShadowTrackr search language, e.g. index=hosts problem=yes",
        require=True,
    )
    account = Option(doc="ShadowTrackr account (default: the only configured account)", require=False)
    max_results = Option(
        doc="Most results to return; 0 for no limit (default 10000)",
        require=False,
        default=DEFAULT_MAX_RESULTS,
        validate=validators.Integer(minimum=0),
    )

    def generate(self):
        searchinfo = self._metadata.searchinfo
        try:
            account, warning = choose_account(list_account_names(search_service(searchinfo)), self.account)
            if warning:
                self.write_warning(warning)
            client = build_client_for_search(searchinfo.session_key, account)
            results, total = run_query(client, self.query, self.max_results)
        except (ValueError, CredentialAccessError) as e:
            self.error_exit(e, str(e))
            return
        except AuthError as e:
            self.error_exit(e, "ShadowTrackr rejected the API key of account '{}': {}. {}.".format(account, e, AUTH_HINT))
            return
        except ShadowTrackrError as e:
            self.error_exit(e, "ShadowTrackr query failed: {}".format(e))
            return

        if total > len(results):
            self.write_warning(
                "ShadowTrackr returned {} rows; showing the first {}. Narrow the query or raise max_results.".format(
                    total, len(results))
            )
        for result in results:
            yield result


dispatch(ShadowTrackrCommand, sys.argv, sys.stdin, sys.stdout, __name__)
