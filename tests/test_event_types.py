from shadowtrackr_lib.event_types import humanize, to_records


def test_to_records_maps_api_rows(fixture_event_types):
    records = to_records(fixture_event_types)
    assert len(records) == len(fixture_event_types)
    renewed = next(r for r in records if r["eventid"] == 1415)
    assert renewed == {
        "_key": "1415",
        "eventid": 1415,
        "name": "ssllabs_renewed_cert_problems",
        "title": "Ssllabs renewed cert problems",
        "category": "certificate",
        "source": "ssl",
        "is_change": "true",
        "default_level": 91,
        "aliases": "",
    }


def test_to_records_handles_nulls_aliases_and_titles():
    rows = [
        {"eventid": 219, "name": "port_closed", "category": "host", "default_level": None, "is_change": True,
         "aliases": ["port_removed"]},
        {"eventid": 7, "name": "x", "title": "Readable title", "category": None, "is_change": "false"},
    ]
    first, second = to_records(rows)
    assert first["default_level"] == "" and first["aliases"] == "port_removed"
    assert second["title"] == "Readable title"
    assert second["category"] == "other" and second["is_change"] == "false"


def test_to_records_skips_invalid_and_duplicate_rows():
    rows = [{"eventid": "12"}, {"eventid": True}, "junk", {"eventid": 5, "name": "a"}, {"eventid": 5, "name": "b"}]
    assert [r["name"] for r in to_records(rows)] == ["a"]


def test_humanize():
    assert humanize("ssllabs_renewed_cert_problems") == "Ssllabs renewed cert problems"
    assert humanize("") == ""
