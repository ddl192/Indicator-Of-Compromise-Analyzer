"""
Tests for `virustotal_api.VirusTotalAPI`.

We mock `requests.Session.get` / `.post` so no real network calls happen.
We also patch `time.sleep` so the retry/poll logic doesn't actually wait —
tests run in milliseconds.
"""

import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src"))
)
from virustotal_api import VirusTotalAPI, _VTCache, load_vt_config  # noqa: E402


# ── Helpers ─────────────────────────────────────────────────────────────────


def _resp(status: int, body=None, headers=None):
    """Build a fake `requests.Response`."""
    r = mock.MagicMock()
    r.status_code = status
    r.text = json.dumps(body) if body is not None else ""
    r.headers = headers or {}
    if body is None:
        r.json.side_effect = ValueError("no body")
    else:
        r.json.return_value = body
    return r


def _ok_file(file_id="44d88612fea8a8f36de82e1278abb02f", malicious=10, total=70):
    return {
        "data": {
            "id": file_id,
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": total - malicious,
                    "timeout": 0,
                },
                "reputation": -50,
            },
        }
    }


def _make_client(**overrides):
    """Construct a VT client with no rate-limit pacing and no disk cache."""
    defaults = dict(
        api_key="test-key",
        rate_limit_delay=0,
        request_timeout=5,
        max_retries=4,
        cache_path=None,
        cache_ttl_hours=24,
        negative_cache_ttl_hours=4,
        url_poll_attempts=3,
        url_poll_interval=0.01,
    )
    defaults.update(overrides)
    return VirusTotalAPI(**defaults)


# ── Cache tests (pure, no HTTP) ─────────────────────────────────────────────


class TestVTCache(unittest.TestCase):
    def test_in_memory_get_set(self):
        c = _VTCache(path=None)
        self.assertEqual(c.get("ip", "1.2.3.4"), (False, None))
        c.set("ip", "1.2.3.4", {"malicious": 5})
        found, data = c.get("ip", "1.2.3.4")
        self.assertTrue(found)
        self.assertEqual(data, {"malicious": 5})

    def test_negative_caching(self):
        c = _VTCache(path=None)
        c.set("ip", "9.9.9.9", None)
        found, data = c.get("ip", "9.9.9.9")
        self.assertTrue(found)
        self.assertIsNone(data)

    def test_ttl_expiry(self):
        c = _VTCache(path=None, ttl_seconds=0)  # expires immediately
        c.set("ip", "1.2.3.4", {"x": 1})
        found, _ = c.get("ip", "1.2.3.4")
        self.assertFalse(found)

    def test_persist_and_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "cache.json")
            c1 = _VTCache(path=path)
            c1.set("hash", "abc", {"malicious": 3})
            c1.set("ip", "1.1.1.1", None)  # negative cache
            c1.flush()
            self.assertTrue(os.path.exists(path))

            c2 = _VTCache(path=path)
            found1, data1 = c2.get("hash", "abc")
            self.assertTrue(found1)
            self.assertEqual(data1, {"malicious": 3})
            found2, data2 = c2.get("ip", "1.1.1.1")
            self.assertTrue(found2)
            self.assertIsNone(data2)

    def test_corrupt_cache_starts_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "cache.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write("{garbage")
            c = _VTCache(path=path)
            self.assertEqual(c.get("ip", "1.2.3.4"), (False, None))


# ── HTTP-mocked tests for VirusTotalAPI ─────────────────────────────────────


@mock.patch("virustotal_api.time.sleep", lambda *_: None)
class TestVirusTotalAPIRequests(unittest.TestCase):
    def test_check_file_hash_happy_path(self):
        vt = _make_client()
        with mock.patch.object(vt._session, "get", return_value=_resp(200, _ok_file())) as g:
            r = vt.check_file_hash("44d88612fea8a8f36de82e1278abb02f")
        self.assertIsNotNone(r)
        self.assertEqual(r["type"], "file")
        self.assertEqual(r["malicious"], 10)
        self.assertEqual(r["total_engines"], 70)
        self.assertEqual(r["detection_ratio"], "10/70")
        self.assertEqual(r["reputation"], -50)
        # Endpoint shape
        self.assertEqual(g.call_count, 1)
        self.assertIn("files/44d88612fea8a8f36de82e1278abb02f", g.call_args[0][0])

    def test_file_result_preserves_queried_hash(self):
        """When user queries an MD5 but VT returns SHA-256, both must be kept."""
        vt = _make_client()
        # Simulate VT canonicalizing an MD5 lookup to a SHA-256 id.
        sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        md5_query = "44d88612fea8a8f36de82e1278abb02f"
        body = {
            "data": {
                "id": sha256,
                "attributes": {
                    "last_analysis_stats": {"malicious": 65, "harmless": 2,
                                            "undetected": 0, "suspicious": 0,
                                            "timeout": 0},
                    "md5": md5_query,
                    "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
                    "sha256": sha256,
                    "reputation": 0,
                },
            }
        }
        with mock.patch.object(vt._session, "get", return_value=_resp(200, body)):
            r = vt.check_file_hash(md5_query)
        self.assertIsNotNone(r)
        # User's hash is preserved verbatim.
        self.assertEqual(r["queried_hash"], md5_query)
        # VT's canonical SHA-256 stays available too.
        self.assertEqual(r["sha256"], sha256)
        self.assertEqual(r["hash"], sha256)            # backwards-compat
        self.assertEqual(r["md5"], md5_query)
        self.assertEqual(r["sha1"], "3395856ce81f2b7382dee72602f798b642f14140")
        self.assertEqual(r["malicious"], 65)
        self.assertEqual(r["detection_ratio"], "65/67")

    def test_returns_none_on_404(self):
        vt = _make_client()
        with mock.patch.object(vt._session, "get", return_value=_resp(404)):
            self.assertIsNone(vt.check_file_hash("deadbeef" * 8))

    def test_negative_result_is_cached(self):
        """A 404 should be cached so we don't hit the API again."""
        vt = _make_client()
        with mock.patch.object(vt._session, "get", return_value=_resp(404)) as g:
            self.assertIsNone(vt.check_file_hash("dead"))
            self.assertIsNone(vt.check_file_hash("dead"))
        # Only one HTTP call — second is cache hit.
        self.assertEqual(g.call_count, 1)

    def test_positive_result_is_cached(self):
        vt = _make_client()
        with mock.patch.object(vt._session, "get", return_value=_resp(200, _ok_file())) as g:
            r1 = vt.check_file_hash("h1")
            r2 = vt.check_file_hash("h1")
        self.assertEqual(r1, r2)
        self.assertEqual(g.call_count, 1)

    def test_429_then_success_with_retry_after(self):
        vt = _make_client()
        responses = [
            _resp(429, headers={"Retry-After": "0"}),
            _resp(200, _ok_file()),
        ]
        with mock.patch.object(vt._session, "get", side_effect=responses) as g:
            r = vt.check_file_hash("h1")
        self.assertIsNotNone(r)
        self.assertEqual(g.call_count, 2)

    def test_429_unbounded_retry_eventually_gives_up(self):
        """v1 had infinite recursion on persistent 429 — v3 must NOT."""
        vt = _make_client(max_retries=3)
        with mock.patch.object(vt._session, "get",
                               return_value=_resp(429, headers={"Retry-After": "0"})) as g:
            r = vt.check_file_hash("h1")
        self.assertIsNone(r)
        # Bounded by max_retries (we don't insist on exact count, only finite).
        self.assertEqual(g.call_count, 3)
        self.assertLessEqual(g.call_count, 3)

    def test_5xx_retries_then_succeeds(self):
        vt = _make_client(max_retries=3)
        responses = [_resp(500), _resp(503), _resp(200, _ok_file())]
        with mock.patch.object(vt._session, "get", side_effect=responses) as g:
            r = vt.check_file_hash("h1")
        self.assertIsNotNone(r)
        self.assertEqual(g.call_count, 3)

    def test_4xx_other_than_429_403_404_gives_up(self):
        vt = _make_client(max_retries=3)
        with mock.patch.object(vt._session, "get", return_value=_resp(418)) as g:
            r = vt.check_file_hash("h1")
        self.assertIsNone(r)
        self.assertEqual(g.call_count, 1)

    def test_403_returns_none_immediately(self):
        vt = _make_client()
        with mock.patch.object(vt._session, "get", return_value=_resp(403)) as g:
            r = vt.check_file_hash("h1")
        self.assertIsNone(r)
        self.assertEqual(g.call_count, 1)

    def test_check_ip_address_endpoint(self):
        vt = _make_client()
        body = {"data": {"id": "8.8.8.8",
                         "attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 80}}}}
        with mock.patch.object(vt._session, "get", return_value=_resp(200, body)) as g:
            r = vt.check_ip_address("8.8.8.8")
        self.assertEqual(r["type"], "ip")
        self.assertEqual(r["address"], "8.8.8.8")
        self.assertIn("ip_addresses/8.8.8.8", g.call_args[0][0])

    def test_check_domain_endpoint(self):
        vt = _make_client()
        body = {"data": {"id": "evil.com",
                         "attributes": {"last_analysis_stats": {"malicious": 5}}}}
        with mock.patch.object(vt._session, "get", return_value=_resp(200, body)) as g:
            r = vt.check_domain("EVIL.COM")
        self.assertEqual(r["type"], "domain")
        self.assertEqual(r["domain"], "evil.com")
        # Lowercased before being put into the URL
        self.assertIn("domains/evil.com", g.call_args[0][0])

    def test_check_url_uses_base64_id_first(self):
        """The first GET should hit the canonical url-safe-base64 ID."""
        vt = _make_client()
        # 200 on first call → no submit/poll.
        with mock.patch.object(vt._session, "get",
                               return_value=_resp(200, _ok_file())) as g:
            r = vt.check_url("http://evil.com/x")
        self.assertIsNotNone(r)
        # Verify the URL contains the base64 form (no '=' padding).
        called_url = g.call_args_list[0][0][0]
        # It's base64-url-safe of "http://evil.com/x" which is short enough not to have padding
        # We just sanity-check it's not the sha256 hex (64-char [a-f0-9])
        path_id = called_url.split("/urls/")[1]
        self.assertFalse(len(path_id) == 64 and all(c in "0123456789abcdef" for c in path_id))

    def test_check_url_falls_back_to_sha256_then_submits_and_polls(self):
        vt = _make_client(url_poll_attempts=2, url_poll_interval=0)
        # 1) base64 lookup → 404
        # 2) sha256 lookup → 404
        # 3) submit returns analysis id
        # 4) first poll: queued
        # 5) second poll: completed
        get_responses = [
            _resp(404),
            _resp(404),
            _resp(200, {"data": {"attributes": {"status": "queued"}}}),
            _resp(200, {"data": {"attributes": {
                "status": "completed",
                "stats": {"malicious": 7, "harmless": 13, "undetected": 0,
                          "suspicious": 0, "timeout": 0},
            }}}),
        ]
        post_response = _resp(200, {"data": {"id": "ANALYSIS123"}})
        with mock.patch.object(vt._session, "get", side_effect=get_responses) as g, \
             mock.patch.object(vt._session, "post", return_value=post_response) as p:
            r = vt.check_url("http://unknown.example/x")
        self.assertIsNotNone(r)
        self.assertEqual(r["type"], "url")
        self.assertEqual(r["malicious"], 7)
        self.assertEqual(r["total_engines"], 20)
        self.assertEqual(p.call_count, 1)  # submitted once
        # 2 lookups + 2 polls = 4 GETs
        self.assertEqual(g.call_count, 4)

    def test_url_submission_polling_times_out(self):
        vt = _make_client(url_poll_attempts=2, url_poll_interval=0)
        get_responses = [
            _resp(404),
            _resp(404),
            _resp(200, {"data": {"attributes": {"status": "queued"}}}),
            _resp(200, {"data": {"attributes": {"status": "queued"}}}),
        ]
        with mock.patch.object(vt._session, "get", side_effect=get_responses), \
             mock.patch.object(vt._session, "post",
                               return_value=_resp(200, {"data": {"id": "A"}})):
            r = vt.check_url("http://unknown.example/x")
        self.assertIsNone(r)
        # And the negative result gets cached.
        with mock.patch.object(vt._session, "get") as g2, \
             mock.patch.object(vt._session, "post") as p2:
            r2 = vt.check_url("http://unknown.example/x")
            self.assertIsNone(r2)
            self.assertEqual(g2.call_count, 0)
            self.assertEqual(p2.call_count, 0)


# ── Batch + dedup tests ─────────────────────────────────────────────────────


@mock.patch("virustotal_api.time.sleep", lambda *_: None)
class TestBatchCheckIocs(unittest.TestCase):
    def test_dedups_input_and_skips_blanks(self):
        vt = _make_client()
        with mock.patch.object(vt, "check_file_hash",
                               return_value={"type": "file", "hash": "h1",
                                             "malicious": 0, "detection_ratio": "0/70"}) as cfh:
            results = vt.batch_check_iocs([
                ("hash", "h1"),
                ("hash", "h1"),       # duplicate
                ("hash", "  "),        # blank
                ("hash", ""),          # blank
            ])
        self.assertEqual(cfh.call_count, 1)
        self.assertEqual(len(results), 1)
        self.assertIn("hash_h1", results)

    def test_unsupported_type_is_skipped(self):
        vt = _make_client()
        results = vt.batch_check_iocs([("garbage", "x")])
        self.assertEqual(results, {})

    def test_one_failure_does_not_kill_batch(self):
        vt = _make_client()
        with mock.patch.object(vt, "check_file_hash",
                               side_effect=[RuntimeError("boom"),
                                            {"type": "file", "hash": "h2",
                                             "malicious": 1, "detection_ratio": "1/70"}]):
            results = vt.batch_check_iocs([("hash", "h1"), ("hash", "h2")])
        self.assertNotIn("hash_h1", results)
        self.assertIn("hash_h2", results)


# ── Free function ───────────────────────────────────────────────────────────


class TestLoadVTConfig(unittest.TestCase):
    def test_missing_file(self):
        self.assertIsNone(load_vt_config("/nonexistent.json"))

    def test_returns_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "vt.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"api_key": "abc"}, f)
            self.assertEqual(load_vt_config(path), "abc")

    def test_empty_string_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "vt.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"api_key": ""}, f)
            self.assertIsNone(load_vt_config(path))

    def test_invalid_json_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "vt.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write("{not valid")
            self.assertIsNone(load_vt_config(path))


# ── Constructor / context manager ───────────────────────────────────────────


class TestVTConstructor(unittest.TestCase):
    def test_missing_key_raises(self):
        # Make sure env var doesn't sneak in.
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                VirusTotalAPI(api_key=None)

    def test_env_var_fallback(self):
        with mock.patch.dict(os.environ, {"VT_API_KEY": "from-env"}):
            vt = VirusTotalAPI(api_key=None, rate_limit_delay=0, cache_path=None)
        self.assertEqual(vt.api_key, "from-env")
        vt.close()

    def test_context_manager_flushes_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "cache.json")
            with VirusTotalAPI(
                api_key="k", rate_limit_delay=0, cache_path=path
            ) as vt:
                vt._cache.set("hash", "abc", {"malicious": 1})
            self.assertTrue(os.path.exists(path))


if __name__ == "__main__":
    unittest.main()
