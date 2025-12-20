import textwrap
from bsqli.modules.blind_sqli.sqli_module import BlindSQLiModule
from bsqli.core.raw_parser import parse_raw_request


def test_scan_raw_request_invokes_all_detectors(monkeypatch):
    module = BlindSQLiModule(timeout=0)
    calls = {
        "boolean": [],
        "time": [],
        "boolean_form": [],
        "time_form": [],
        "boolean_cookie": [],
        "time_cookie": [],
    }

    class DummyDetector:
        def detect_boolean(self, url, param, headers=None, cookies=None):
            calls["boolean"].append((url, param))
            return {"evidence": [{"ok": True}]}

        def detect_time(self, url, param, headers=None, cookies=None):
            calls["time"].append((url, param))
            return {"evidence": [{"ok": True}]}

        def detect_boolean_form(self, url, param, base_data, headers=None, cookies=None):
            calls["boolean_form"].append((url, param))
            return {"evidence": [{"ok": True}]}

        def detect_time_form(self, url, param, base_data, headers=None, cookies=None):
            calls["time_form"].append((url, param))
            return {"evidence": [{"ok": True}]}

        def detect_boolean_cookie(self, url, cookie_name, cookies, headers=None):
            calls["boolean_cookie"].append((url, cookie_name))
            return {"evidence": [{"ok": True}]}

        def detect_time_cookie(self, url, cookie_name, cookies, headers=None):
            calls["time_cookie"].append((url, cookie_name))
            return {"evidence": [{"ok": True}]}

    module.detector = DummyDetector()

    raw = {
        "method": "POST",
        "url": "http://example.com/search?q=1",
        "headers": {"Content-Type": "application/x-www-form-urlencoded", "Host": "example.com"},
        "cookies": {"session": "abc123"},
        "body": "name=alice&role=admin",
        "content_type": "application/x-www-form-urlencoded",
    }

    findings = module.scan_raw_request(raw)

    assert len(findings) == 8  # boolean/time for query + boolean/time per form field + boolean/time cookie
    assert len(calls["boolean"]) == 1
    assert len(calls["time"]) == 1
    assert len(calls["boolean_form"]) == 2
    assert len(calls["time_form"]) == 2
    assert len(calls["boolean_cookie"]) == 1
    assert len(calls["time_cookie"]) == 1


def test_parse_raw_request_parses_basic_fields(tmp_path):
    raw_path = tmp_path / "raw.txt"
    raw_path.write_text(
        textwrap.dedent(
            """
            POST /path?foo=1 HTTP/1.1
            Host: example.com
            Cookie: a=1; b=2
            Content-Type: application/x-www-form-urlencoded

            id=10
            """
        ).strip()
    )

    parsed = parse_raw_request(str(raw_path))

    assert parsed["method"] == "POST"
    assert parsed["url"] == "http://example.com/path?foo=1"
    assert parsed["cookies"] == {"a": "1", "b": "2"}
    assert parsed["body"] == "id=10"
