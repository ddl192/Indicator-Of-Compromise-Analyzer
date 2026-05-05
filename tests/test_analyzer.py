"""
Unit tests for the IOC analyzer.

Backwards-compatible with the original test file: `test_load_iocs`,
`test_search_iocs`, `test_search_urls` are kept verbatim. The rest are
new tests covering the hardening work.

Run from repo root:
    python -m unittest tests.test_analyzer

Or from the tests/ folder:
    python test_analyzer.py
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src"))
)
from analyzer import (  # noqa: E402  (intentional after sys.path tweak)
    load_iocs,
    search_iocs,
    process_log_file,
    save_alerts,
    _domain_in_text,
    _extract_iocs_from_text,
    _ioc_value_from_result,
    load_vt_config_file,
)


SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../src"))
TESTS_DIR = os.path.abspath(os.path.dirname(__file__))


# ── Original tests (must keep passing) ────────────────────────────────────


class TestAnalyzer(unittest.TestCase):
    def test_load_iocs(self):
        iocs = load_iocs(os.path.join(SRC_DIR, "ioc_list.json"))
        self.assertIn("ips", iocs)
        self.assertIsInstance(iocs["ips"], list)

    def test_search_iocs(self):
        iocs = {"ips": ["1.2.3.4"], "domains": [], "file_hashes": [], "urls": []}
        result = search_iocs("Connection from 1.2.3.4 detected", iocs)
        self.assertIn(("ip", "1.2.3.4"), result)

    def test_search_urls(self):
        iocs = {
            "ips": [], "domains": [], "file_hashes": [],
            "urls": ["http://example.com/malicious"],
        }
        result = search_iocs("Accessing http://example.com/malicious", iocs)
        self.assertIn(("url", "http://example.com/malicious"), result)


# ── New tests ─────────────────────────────────────────────────────────────


class TestLoadIocsRobustness(unittest.TestCase):
    """`load_iocs` must never raise and always returns the canonical shape."""

    EXPECTED_KEYS = {"ips", "domains", "file_hashes", "urls"}

    def _write(self, content):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        self.addCleanup(os.unlink, path)
        return path

    def test_missing_file_returns_empty(self):
        result = load_iocs("/nonexistent/path/__nope.json")
        self.assertEqual(set(result.keys()), self.EXPECTED_KEYS)
        self.assertEqual(result["ips"], [])

    def test_invalid_json_returns_empty(self):
        path = self._write("{not valid json")
        result = load_iocs(path)
        self.assertEqual(set(result.keys()), self.EXPECTED_KEYS)
        self.assertEqual(result["ips"], [])

    def test_root_must_be_object(self):
        path = self._write(json.dumps([1, 2, 3]))
        result = load_iocs(path)
        self.assertEqual(result["ips"], [])

    def test_skips_non_string_entries(self):
        path = self._write(json.dumps({
            "ips": ["1.1.1.1", 42, None, "  ", "2.2.2.2"],
            "domains": ["evil.com", "", 7],
        }))
        result = load_iocs(path)
        self.assertEqual(result["ips"], ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(result["domains"], ["evil.com"])

    def test_lowercases_non_url_keys(self):
        path = self._write(json.dumps({
            "ips": ["8.8.8.8"],
            "domains": ["EVIL.COM"],
            "file_hashes": ["DEADBEEF" * 8],
            "urls": ["HTTP://EVIL.COM/Path"],
        }))
        result = load_iocs(path)
        self.assertEqual(result["domains"], ["evil.com"])
        self.assertEqual(result["file_hashes"], ["deadbeef" * 8])
        # URLs preserve case
        self.assertEqual(result["urls"], ["HTTP://EVIL.COM/Path"])

    def test_dedups_entries(self):
        path = self._write(json.dumps({"ips": ["1.1.1.1", "1.1.1.1", "2.2.2.2"]}))
        result = load_iocs(path)
        self.assertEqual(result["ips"], ["1.1.1.1", "2.2.2.2"])

    def test_strips_markdown_autolink(self):
        """`[example.com](http://example.com)` → `example.com` for domain entries."""
        path = self._write(json.dumps({
            "domains": ["[example.com](http://example.com)"],
            "urls": ["[link](http://evil.example/payload)"],
        }))
        result = load_iocs(path)
        self.assertEqual(result["domains"], ["example.com"])
        self.assertEqual(result["urls"], ["http://evil.example/payload"])

    def test_strips_angle_brackets(self):
        path = self._write(json.dumps({"urls": ["<http://evil.example/x>"]}))
        result = load_iocs(path)
        self.assertEqual(result["urls"], ["http://evil.example/x"])

    def test_strips_quotes_and_whitespace(self):
        path = self._write(json.dumps({
            "ips": ["  '1.2.3.4'  ", '"5.6.7.8"'],
        }))
        result = load_iocs(path)
        self.assertEqual(sorted(result["ips"]), ["1.2.3.4", "5.6.7.8"])

    def test_un_defangs_iocs(self):
        path = self._write(json.dumps({
            "domains": ["evil[.]example"],
            "ips": ["1.2.3[.]4"],
            "urls": ["hxxps://bad[.]example/path"],
        }))
        result = load_iocs(path)
        self.assertEqual(result["domains"], ["evil.example"])
        self.assertEqual(result["ips"], ["1.2.3.4"])
        self.assertEqual(result["urls"], ["https://bad.example/path"])


class TestSearchIocs(unittest.TestCase):
    def test_domain_word_boundary(self):
        """Domains must NOT match label-substrings (this was a bug in v1)."""
        iocs = {"ips": [], "domains": ["evil.com"], "file_hashes": [], "urls": []}
        # 'notevil.com' contains 'evil.com' as a substring but not as a label.
        self.assertEqual(search_iocs("ping notevil.com here", iocs), [])
        # Standalone match still works.
        self.assertIn(("domain", "evil.com"),
                      search_iocs("ping evil.com here", iocs))
        # Subdomain still hits the parent.
        self.assertIn(("domain", "evil.com"),
                      search_iocs("ping x.evil.com here", iocs))

    def test_no_false_positives_on_known_traps(self):
        """End-to-end: realistic IOC list + log lines with FP traps must yield 0 FP."""
        iocs = {
            "ips": ["1.2.3.4", "203.0.113.45", "185.220.101.50"],
            "domains": ["example.com"],
            "file_hashes": ["44d88612fea8a8f36de82e1278abb02f"],
            "urls": ["http://example.com/malicious"],
        }
        # Lines that contain FP-bait but no real IOC.
        fp_bait_lines = [
            '11.2.3.45 - - "GET / HTTP/1.1" 200 4096 "-" "Mozilla/5.0"',  # IP substring
            '21.2.3.41 - - "GET / HTTP/1.1" 200 4096 "-" "Mozilla/5.0"',  # IP substring
            '1.2.3.45 - - "GET / HTTP/1.1" 200 4096 "-" "Mozilla/5.0"',   # IP right-extension
            '1.2.3.49 - - "GET / HTTP/1.1" 200 4096 "-" "Mozilla/5.0"',
            'Referer "https://notexample.com/"',                          # domain substring
            'mailto:contact@notexample.com',                              # domain substring
            '203.0.113.450 - extra digit',                                # IP right-extension
        ]
        for line in fp_bait_lines:
            self.assertEqual(
                search_iocs(line, iocs), [],
                f"False positive on bait line: {line!r}"
            )

        # Lines that DO contain a real IOC must match exactly that one.
        positive_cases = [
            ('1.2.3.4 - - "GET /" 200', ('ip', '1.2.3.4')),
            ('Referer: https://example.com/page', ('domain', 'example.com')),
            ('?h=44d88612fea8a8f36de82e1278abb02f', ('hash', '44d88612fea8a8f36de82e1278abb02f')),
            ('GET http://example.com/malicious HTTP', ('url', 'http://example.com/malicious')),
        ]
        for line, expected in positive_cases:
            self.assertIn(expected, search_iocs(line, iocs),
                          f"Missed positive: {expected} on {line!r}")

    def test_ip_boundary_does_not_match_inside_longer_ip(self):
        """`1.2.3.4` must NOT match inside `11.2.3.45`. Reported by user."""
        iocs = {"ips": ["1.2.3.4"], "domains": [], "file_hashes": [], "urls": []}
        # Apache log line - IOC 1.2.3.4 should NOT match the source IP 11.2.3.45.
        line = '11.2.3.45 - - [01/May/2026:10:41:22 +0000] "GET /metrics HTTP/1.1" 304 256'
        self.assertEqual(search_iocs(line, iocs), [])
        # And `1.2.3.4` must also not match `1.2.3.45` or `1.2.3.40`.
        self.assertEqual(search_iocs("from 1.2.3.45 came", iocs), [])
        self.assertEqual(search_iocs("from 1.2.3.40 came", iocs), [])
        # Real match still works (the original test).
        self.assertIn(("ip", "1.2.3.4"),
                      search_iocs("Connection from 1.2.3.4 detected", iocs))
        # And at end of line / followed by punctuation.
        self.assertIn(("ip", "1.2.3.4"), search_iocs("source=1.2.3.4", iocs))
        self.assertIn(("ip", "1.2.3.4"), search_iocs("[1.2.3.4]", iocs))
        self.assertIn(("ip", "1.2.3.4"), search_iocs("ip 1.2.3.4.", iocs))

    def test_per_call_dedup(self):
        iocs = {"ips": ["1.2.3.4"], "domains": [], "file_hashes": [], "urls": []}
        # Identical IOC appears twice in the line → returned once.
        result = search_iocs("from 1.2.3.4 then 1.2.3.4 again", iocs)
        self.assertEqual(result.count(("ip", "1.2.3.4")), 1)

    def test_empty_text(self):
        self.assertEqual(search_iocs("", {"ips": ["1.2.3.4"]}), [])

    def test_non_string_text(self):
        self.assertEqual(search_iocs(None, {"ips": ["1.2.3.4"]}), [])  # type: ignore[arg-type]

    def test_url_case_insensitive_and_exact(self):
        iocs = {"ips": [], "domains": [], "file_hashes": [],
                "urls": ["http://Evil.COM/Path"]}
        self.assertIn(("url", "http://Evil.COM/Path"),
                      search_iocs("hit http://Evil.COM/Path now", iocs))
        self.assertIn(("url", "http://Evil.COM/Path"),
                      search_iocs("hit http://evil.com/path now", iocs))

    def test_skips_blank_iocs(self):
        iocs = {"ips": ["", "  "], "domains": [""], "file_hashes": [""],
                "urls": [""]}
        self.assertEqual(search_iocs("anything goes 1.1.1.1", iocs), [])


class TestDomainBoundary(unittest.TestCase):
    def test_helper_directly(self):
        self.assertTrue(_domain_in_text("evil.com", "ping evil.com today"))
        self.assertFalse(_domain_in_text("evil.com", "ping notevil.com today"))
        self.assertTrue(_domain_in_text("evil.com", "x.evil.com is bad"))
        self.assertFalse(_domain_in_text("", "irrelevant"))


class TestRegexAutoExtract(unittest.TestCase):
    def test_extracts_url_ip_hash(self):
        line = ("GET https://evil.com/path?x=1 from 8.8.8.8 hash="
                "44d88612fea8a8f36de82e1278abb02f")
        hits = set(_extract_iocs_from_text(line))
        self.assertIn(("url", "https://evil.com/path?x=1"), hits)
        self.assertIn(("ip", "8.8.8.8"), hits)
        self.assertIn(("hash", "44d88612fea8a8f36de82e1278abb02f"), hits)
        # URL host should NOT also appear as a separate domain IOC.
        self.assertNotIn(("domain", "evil.com"), hits)

    def test_skips_private_and_special_ips(self):
        ips = [v for t, v in _extract_iocs_from_text(
            "Internal 192.168.1.1 -> 10.0.0.5; ext 1.2.3.4 ; loop 127.0.0.1"
        ) if t == "ip"]
        self.assertEqual(ips, ["1.2.3.4"])

    def test_no_double_hash_for_sha256(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        hashes = [v for t, v in _extract_iocs_from_text(f"sample={sha256}")
                  if t == "hash"]
        self.assertEqual(hashes, [sha256])

    def test_strips_url_trailing_punct(self):
        urls = [v for t, v in _extract_iocs_from_text(
            "See (https://bad.example/path)."
        ) if t == "url"]
        self.assertIn("https://bad.example/path", urls)

    def test_skips_file_extensions_as_domains(self):
        """`wp-admin.php`, `index.html`, `config.php` must NOT be flagged as domains."""
        line = 'GET /wp-admin.php and /admin/config.php and /index.html ; go to evil.com'
        domains = [v for t, v in _extract_iocs_from_text(line) if t == "domain"]
        self.assertNotIn("wp-admin.php", domains)
        self.assertNotIn("config.php", domains)
        self.assertNotIn("index.html", domains)
        # Real domain still detected.
        self.assertIn("evil.com", domains)

    def test_multi_label_with_extlike_suffix_still_passes(self):
        """We only suppress 2-label cases; sub.domain.<ext-like> stays."""
        # `app.example.dev` looks like a real hostname even though `dev` is
        # also a valid TLD, so we keep multi-label hostnames untouched.
        domains = [v for t, v in _extract_iocs_from_text(
            "see app.example.dev now"
        ) if t == "domain"]
        self.assertIn("app.example.dev", domains)


class TestProcessLogFile(unittest.TestCase):
    def test_alerts_collected(self):
        iocs = {"ips": ["1.2.3.4"], "domains": [], "file_hashes": [], "urls": []}
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "test.log")
            with open(log_path, "w", encoding="utf-8") as f:
                f.write("nothing here\n")
                f.write("hit 1.2.3.4 in this line\n")
                f.write("clean again\n")
            alerts = []
            process_log_file(log_path, iocs, alerts, quiet=True)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["ioc_type"], "ip")
            self.assertEqual(alerts[0]["pattern"], "1.2.3.4")

    def test_missing_file_no_crash(self):
        alerts = []
        process_log_file("/nonexistent.log",
                         {"ips": ["1.2.3.4"]}, alerts, quiet=True)
        self.assertEqual(alerts, [])

    def test_auto_extract_finds_unlisted_ioc(self):
        iocs = {"ips": [], "domains": [], "file_hashes": [], "urls": []}
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "test.log")
            with open(log_path, "w", encoding="utf-8") as f:
                f.write("client=66.249.66.1 ua=Googlebot\n")
            alerts = []
            process_log_file(log_path, iocs, alerts,
                             auto_extract=True, quiet=True)
            ips = [a["pattern"] for a in alerts if a["ioc_type"] == "ip"]
            self.assertIn("66.249.66.1", ips)


class TestSaveAlerts(unittest.TestCase):
    def test_writes_csv_with_correct_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "alerts.csv")
            save_alerts(
                [{"file": "x.log", "ioc_type": "ip",
                  "pattern": "1.2.3.4", "line": "hit"}],
                out,
            )
            self.assertTrue(os.path.exists(out))
            with open(out, encoding="utf-8") as f:
                first_line = f.readline().strip()
            self.assertEqual(first_line, "file,ioc_type,pattern,line")

    def test_creates_missing_outdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "nested", "deep", "alerts.csv")
            save_alerts([], out)
            self.assertTrue(os.path.exists(out))


class TestLoadVTConfigFile(unittest.TestCase):
    def test_missing_file_returns_none(self):
        self.assertIsNone(load_vt_config_file("/nonexistent.json"))

    def test_merges_with_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = os.path.join(tmp, "vt.json")
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump({"api_key": "k", "rate_limit_delay": 2}, f)
            cfg = load_vt_config_file(cfg_path)
            assert cfg is not None
            self.assertEqual(cfg["api_key"], "k")
            self.assertEqual(cfg["rate_limit_delay"], 2)
            # New defaults must be present.
            self.assertIn("cache_enabled", cfg)
            self.assertIn("max_retries", cfg)

    def test_invalid_json_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = os.path.join(tmp, "vt.json")
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write("{not valid")
            self.assertIsNone(load_vt_config_file(cfg_path))


class TestIocValueFromResult(unittest.TestCase):
    def test_file_prefers_queried_hash(self):
        """Summary lines must show the user's MD5, not VT's canonical SHA-256."""
        result = {
            "type": "file",
            "hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "queried_hash": "44d88612fea8a8f36de82e1278abb02f",
            "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "md5": "44d88612fea8a8f36de82e1278abb02f",
        }
        self.assertEqual(_ioc_value_from_result(result),
                         "44d88612fea8a8f36de82e1278abb02f")

    def test_file_falls_back_to_hash_when_no_queried(self):
        result = {"type": "file", "hash": "abc"}
        self.assertEqual(_ioc_value_from_result(result), "abc")

    def test_ip(self):
        self.assertEqual(_ioc_value_from_result({"address": "1.2.3.4"}), "1.2.3.4")

    def test_domain(self):
        self.assertEqual(_ioc_value_from_result({"domain": "evil.com"}), "evil.com")

    def test_url(self):
        self.assertEqual(_ioc_value_from_result({"url": "http://x"}), "http://x")

    def test_unknown_default(self):
        self.assertEqual(_ioc_value_from_result({}), "unknown")


if __name__ == "__main__":
    unittest.main()
