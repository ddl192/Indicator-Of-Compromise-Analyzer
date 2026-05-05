"""
VirusTotal API v3 client — hardened, drop-in compatible.

Public API kept identical to the original:
    VirusTotalAPI(api_key)
        .check_file_hash(h) -> dict | None
        .check_ip_address(ip) -> dict | None
        .check_domain(d) -> dict | None
        .check_url(u) -> dict | None
        .batch_check_iocs(list[(type, value)]) -> dict[str, dict]
        .save_results(results, filename)

    load_vt_config(config_file) -> str | None

Improvements (no breaking changes):
  • Bounded retry with exponential backoff + jitter (no infinite recursion on 429).
  • Honors the Retry-After header when present.
  • Persistent JSON cache on disk (positive + negative TTL) to survive 4 req/min.
  • URL identifier uses URL-safe base64 (canonical VT v3 form), with sha256 fallback.
  • URL submission with proper polling (status == "completed") instead of single sleep.
  • Negative caching for 404s — no re-querying IOCs already known to be unknown.
  • Per-instance request session for connection pooling.
  • All dict results keep the original schema (type, hash/address/domain/url, malicious,
    suspicious, harmless, undetected, total_engines, detection_ratio, reputation).
  • Class is also a context manager — `with VirusTotalAPI(...) as vt:` flushes the cache.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests


__all__ = ["VirusTotalAPI", "load_vt_config"]


# ── Persistent cache ────────────────────────────────────────────────────────


class _VTCache:
    """
    Tiny JSON-on-disk cache keyed by f"{ioc_type}:{value}".

    Stored value:
        {"data": <result-dict-or-None>, "ts": <epoch-seconds>}

    `data is None` means a *negative* cache hit — IOC is known to be absent
    from VirusTotal (404). It uses a shorter TTL by default so we re-check
    eventually.
    """

    def __init__(
        self,
        path: Optional[str] = None,
        ttl_seconds: int = 24 * 3600,
        negative_ttl_seconds: int = 4 * 3600,
    ) -> None:
        self._path: Optional[Path] = Path(path) if path else None
        self._ttl = max(0, int(ttl_seconds))
        self._neg_ttl = max(0, int(negative_ttl_seconds))
        self._store: Dict[str, Dict[str, Any]] = {}
        self._dirty = False
        self._load()

    @staticmethod
    def _key(ioc_type: str, value: str) -> str:
        return f"{ioc_type}:{value}"

    def _load(self) -> None:
        if not self._path or not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                # Accept entries shaped {"data": ..., "ts": ...} only.
                for k, v in raw.items():
                    if isinstance(v, dict) and "ts" in v:
                        self._store[k] = {"data": v.get("data"), "ts": float(v["ts"])}
        except (OSError, ValueError, json.JSONDecodeError):
            # Corrupt cache → start clean.
            self._store = {}

    def get(self, ioc_type: str, value: str) -> Tuple[bool, Optional[dict]]:
        """Return (found, data). `found=True, data=None` is a negative hit."""
        entry = self._store.get(self._key(ioc_type, value))
        if entry is None:
            return False, None
        ttl = self._ttl if entry.get("data") is not None else self._neg_ttl
        if ttl == 0 or (time.time() - float(entry["ts"])) > ttl:
            return False, None
        data = entry.get("data")
        return True, (dict(data) if isinstance(data, dict) else None)

    def set(self, ioc_type: str, value: str, data: Optional[dict]) -> None:
        self._store[self._key(ioc_type, value)] = {"data": data, "ts": time.time()}
        self._dirty = True

    def flush(self) -> None:
        if not self._path or not self._dirty:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(self._path.suffix + ".tmp")
            tmp.write_text(json.dumps(self._store), encoding="utf-8")
            tmp.replace(self._path)
            self._dirty = False
        except OSError as e:
            print(f"[VT cache] Could not write cache: {e}")


# ── VT API client ───────────────────────────────────────────────────────────


class VirusTotalAPI:
    """VirusTotal API v3 client — backwards-compatible with the original."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        rate_limit_delay: float = 1.0,
        request_timeout: float = 30.0,
        max_retries: int = 4,
        cache_path: Optional[str] = None,
        cache_ttl_hours: int = 24,
        negative_cache_ttl_hours: int = 4,
        url_poll_attempts: int = 6,
        url_poll_interval: float = 5.0,
    ) -> None:
        """
        Args:
            api_key: VT v3 API key (or read from VT_API_KEY env var).
            rate_limit_delay: minimum seconds between successful requests.
            request_timeout: per-request timeout (seconds).
            max_retries: bounded retry count for 429/5xx/network errors.
            cache_path: if set, enables persistent JSON cache at this path.
            cache_ttl_hours: positive-cache TTL in hours.
            negative_cache_ttl_hours: TTL for cached 404s (shorter is safer).
            url_poll_attempts: max polls when waiting for a fresh URL analysis.
            url_poll_interval: seconds between url-analysis polls.
        """
        self.api_key = api_key or os.getenv("VT_API_KEY")
        if not self.api_key:
            raise ValueError(
                "VirusTotal API key not found. Set VT_API_KEY environment variable "
                "or pass key to constructor."
            )

        self.base_url = self.BASE_URL
        self.headers: Dict[str, str] = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }
        self.rate_limit_delay = max(0.0, float(rate_limit_delay))
        self._request_timeout = float(request_timeout)
        self._max_retries = max(1, int(max_retries))
        self._url_poll_attempts = max(1, int(url_poll_attempts))
        self._url_poll_interval = max(0.5, float(url_poll_interval))

        self._session = requests.Session()
        self._session.headers.update(self.headers)

        self._cache = _VTCache(
            path=cache_path,
            ttl_seconds=cache_ttl_hours * 3600,
            negative_ttl_seconds=negative_cache_ttl_hours * 3600,
        )

        # Last-success timestamp for spacing requests.
        self._last_call_ts = 0.0

    # ── Context manager helpers (so cache flushes deterministically) ────────

    def __enter__(self) -> "VirusTotalAPI":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        try:
            self._cache.flush()
        finally:
            try:
                self._session.close()
            except Exception:
                pass

    # ── Internal: pacing + bounded retries ──────────────────────────────────

    def _sleep_for_rate_limit(self) -> None:
        if self.rate_limit_delay <= 0:
            return
        elapsed = time.monotonic() - self._last_call_ts
        wait = self.rate_limit_delay - elapsed
        if wait > 0:
            time.sleep(wait)

    def _make_request(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        method: str = "GET",
    ) -> Optional[Dict[str, Any]]:
        """
        Issue a request with bounded retries (no recursion). Returns parsed
        JSON dict, or None on permanent failure / 404 / non-JSON body.
        """
        url = f"{self.base_url}/{endpoint}"

        for attempt in range(self._max_retries):
            self._sleep_for_rate_limit()
            try:
                if method == "POST":
                    # Try JSON first; on 400/403 fall back to form-encoded.
                    response = self._session.post(
                        url, json=params, timeout=self._request_timeout
                    )
                    if response.status_code in (400, 403):
                        response = self._session.post(
                            url, data=params, timeout=self._request_timeout
                        )
                else:
                    response = self._session.get(
                        url, params=params, timeout=self._request_timeout
                    )

                self._last_call_ts = time.monotonic()
                status = response.status_code

                if status == 200:
                    try:
                        return response.json()
                    except (ValueError, json.JSONDecodeError):
                        print("Error: Invalid JSON response from VirusTotal API")
                        return None

                if status == 404:
                    return None

                if status == 401:
                    print("[VT] 401 Unauthorized — bad API key.")
                    return None

                if status == 403:
                    print("[VT] 403 Forbidden — API key may lack access to this endpoint.")
                    if "intelligence/search" in endpoint:
                        print("    (Intelligence Search typically requires a paid plan.)")
                    return None

                if status == 429:
                    # Honor Retry-After if present, else exponential backoff w/ jitter.
                    retry_after = self._parse_retry_after(response)
                    wait = retry_after if retry_after is not None else min(
                        60, 5 * (2 ** attempt) + random.uniform(0, 1.5)
                    )
                    print(f"[VT] 429 rate-limited; sleeping {wait:.1f}s "
                          f"(attempt {attempt + 1}/{self._max_retries}).")
                    time.sleep(wait)
                    continue

                if 500 <= status < 600:
                    wait = 3 * (2 ** attempt) + random.uniform(0, 1.0)
                    print(f"[VT] {status} server error; retrying in {wait:.1f}s.")
                    time.sleep(wait)
                    continue

                # 4xx other than handled above → not retriable.
                print(f"API error: {status} - {response.text[:300]}")
                return None

            except requests.exceptions.Timeout:
                if attempt == self._max_retries - 1:
                    print("[VT] Request timed out (giving up).")
                    return None
                time.sleep(2 * (2 ** attempt) + random.uniform(0, 1.0))
            except requests.exceptions.RequestException as e:
                if attempt == self._max_retries - 1:
                    print(f"Network error: {e}")
                    return None
                time.sleep(2 * (2 ** attempt) + random.uniform(0, 1.0))

        return None

    @staticmethod
    def _parse_retry_after(response: requests.Response) -> Optional[float]:
        val = response.headers.get("Retry-After")
        if val is None:
            return None
        try:
            return max(0.0, float(val))
        except ValueError:
            return None

    # ── Cache helper ────────────────────────────────────────────────────────

    def _cached(self, ioc_type: str, value: str) -> Tuple[bool, Optional[dict]]:
        return self._cache.get(ioc_type, value)

    def _store(self, ioc_type: str, value: str, data: Optional[dict]) -> None:
        self._cache.set(ioc_type, value, data)

    # ── Public per-IOC checks ───────────────────────────────────────────────

    def check_file_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Check a file hash. Returns the parsed result dict or None."""
        if not file_hash or not str(file_hash).strip():
            return None
        h = str(file_hash).strip()
        hit, cached = self._cached("hash", h)
        if hit:
            return cached
        result = self._make_request(f"files/{h}")
        parsed: Optional[dict] = None
        if result and isinstance(result.get("data"), dict):
            parsed = self._parse_file_result(result["data"], queried=h)
        self._store("hash", h, parsed)
        return parsed

    def check_ip_address(self, ip_address: str) -> Optional[Dict[str, Any]]:
        if not ip_address or not str(ip_address).strip():
            return None
        ip = str(ip_address).strip()
        hit, cached = self._cached("ip", ip)
        if hit:
            return cached
        result = self._make_request(f"ip_addresses/{ip}")
        parsed: Optional[dict] = None
        if result and isinstance(result.get("data"), dict):
            parsed = self._parse_ip_result(result["data"])
        self._store("ip", ip, parsed)
        return parsed

    def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        if not domain or not str(domain).strip():
            return None
        d = str(domain).strip().lower()
        hit, cached = self._cached("domain", d)
        if hit:
            return cached
        result = self._make_request(f"domains/{d}")
        parsed: Optional[dict] = None
        if result and isinstance(result.get("data"), dict):
            parsed = self._parse_domain_result(result["data"])
        self._store("domain", d, parsed)
        return parsed

    def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Check a URL. Tries the canonical url-safe-base64 id first, then sha256
        as a fallback. If still unknown, submits the URL and polls for
        analysis completion.
        """
        if not url or not str(url).strip():
            return None
        u = str(url).strip()

        hit, cached = self._cached("url", u)
        if hit:
            return cached

        # 1) Try base64 (canonical VT v3 URL identifier).
        url_id_b64 = base64.urlsafe_b64encode(u.encode("utf-8")).rstrip(b"=").decode("ascii")
        result = self._make_request(f"urls/{url_id_b64}")
        if result and isinstance(result.get("data"), dict):
            parsed = self._parse_url_result(result["data"], u)
            self._store("url", u, parsed)
            return parsed

        # 2) Fall back to legacy sha256 id (older code paths used this).
        url_id_sha = hashlib.sha256(u.encode("utf-8")).hexdigest()
        result = self._make_request(f"urls/{url_id_sha}")
        if result and isinstance(result.get("data"), dict):
            parsed = self._parse_url_result(result["data"], u)
            self._store("url", u, parsed)
            return parsed

        # 3) Submit for analysis and poll.
        submit = self._make_request("urls", params={"url": u}, method="POST")
        analysis_id = (submit or {}).get("data", {}).get("id") if isinstance(submit, dict) else None
        if not analysis_id:
            self._store("url", u, None)
            return None

        for _ in range(self._url_poll_attempts):
            time.sleep(self._url_poll_interval)
            analysis = self._make_request(f"analyses/{analysis_id}")
            if not isinstance(analysis, dict) or not isinstance(analysis.get("data"), dict):
                continue
            attrs = analysis["data"].get("attributes", {}) or {}
            if attrs.get("status") == "completed":
                parsed = self._parse_url_analysis_result(analysis["data"], u)
                self._store("url", u, parsed)
                return parsed

        # Polling timed out — negative cache.
        self._store("url", u, None)
        return None

    # ── Result parsers (schema kept identical to the original) ──────────────

    @staticmethod
    def _stats_totals(stats: Dict[str, Any]) -> Tuple[int, int, int, int, int, int]:
        """Return (malicious, suspicious, harmless, undetected, timeout, total)."""
        if not isinstance(stats, dict):
            stats = {}
        m = int(stats.get("malicious") or 0)
        s = int(stats.get("suspicious") or 0)
        h = int(stats.get("harmless") or 0)
        u = int(stats.get("undetected") or 0)
        t = int(stats.get("timeout") or 0)
        return m, s, h, u, t, m + s + h + u + t

    def _parse_file_result(
        self, data: Dict[str, Any], queried: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Parse a /files/{id} response.

        VT v3 always canonicalizes file IDs to SHA-256 in responses, even
        when the request was made with an MD5 or SHA-1 hash. To avoid the
        confusing "I queried 44d8... but VT returned 275a..." in summaries,
        we record:
          - `queried_hash`: exactly what the user asked for (their MD5/SHA1/SHA256)
          - `hash`: the canonical SHA-256 returned by VT
          - `md5`, `sha1`, `sha256`: all three forms when VT exposes them
        Backwards compat: `hash` keeps the SHA-256 (= `data.id`) the original
        code returned, so existing CSV consumers still work.
        """
        attrs = data.get("attributes", {}) or {}
        m, s, h, u, _, total = self._stats_totals(attrs.get("last_analysis_stats", {}))
        sha256 = data.get("id")
        return {
            "type": "file",
            "hash": sha256,                                       # canonical (SHA-256)
            "queried_hash": queried or sha256,                    # what the user asked for
            "md5": attrs.get("md5"),
            "sha1": attrs.get("sha1"),
            "sha256": attrs.get("sha256") or sha256,
            "malicious": m,
            "suspicious": s,
            "undetected": u,
            "harmless": h,
            "reputation": int(attrs.get("reputation") or 0),
            "total_engines": total,
            "detection_ratio": f"{m}/{total}" if total else "0/0",
        }

    def _parse_ip_result(self, data: Dict[str, Any]) -> Dict[str, Any]:
        attrs = data.get("attributes", {}) or {}
        m, s, h, u, _, total = self._stats_totals(attrs.get("last_analysis_stats", {}))
        return {
            "type": "ip",
            "address": data.get("id"),
            "malicious": m,
            "suspicious": s,
            "undetected": u,
            "harmless": h,
            "reputation": int(attrs.get("reputation") or 0),
            "total_engines": total,
            "detection_ratio": f"{m}/{total}" if total else "0/0",
        }

    def _parse_domain_result(self, data: Dict[str, Any]) -> Dict[str, Any]:
        attrs = data.get("attributes", {}) or {}
        m, s, h, u, _, total = self._stats_totals(attrs.get("last_analysis_stats", {}))
        return {
            "type": "domain",
            "domain": data.get("id"),
            "malicious": m,
            "suspicious": s,
            "undetected": u,
            "harmless": h,
            "reputation": int(attrs.get("reputation") or 0),
            "total_engines": total,
            "detection_ratio": f"{m}/{total}" if total else "0/0",
        }

    def _parse_url_result(self, data: Dict[str, Any], original_url: str) -> Dict[str, Any]:
        attrs = data.get("attributes", {}) or {}
        m, s, h, u, _, total = self._stats_totals(attrs.get("last_analysis_stats", {}))
        return {
            "type": "url",
            "url": original_url,
            "malicious": m,
            "suspicious": s,
            "undetected": u,
            "harmless": h,
            "reputation": int(attrs.get("reputation") or 0),
            "total_engines": total,
            "detection_ratio": f"{m}/{total}" if total else "0/0",
        }

    def _parse_url_analysis_result(self, data: Dict[str, Any], original_url: str) -> Dict[str, Any]:
        attrs = data.get("attributes", {}) or {}
        m, s, h, u, _, total = self._stats_totals(attrs.get("stats", {}))
        return {
            "type": "url",
            "url": original_url,
            "malicious": m,
            "suspicious": s,
            "undetected": u,
            "harmless": h,
            "reputation": 0,
            "total_engines": total,
            "detection_ratio": f"{m}/{total}" if total else "0/0",
        }

    # ── Batch ───────────────────────────────────────────────────────────────

    def batch_check_iocs(
        self, iocs: List[Tuple[str, str]]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Check a list of (ioc_type, value) tuples.

        Returns {f"{type}_{value}": result_dict} — same key shape as the original.
        Duplicates are silently skipped (original would query twice).
        """
        results: Dict[str, Dict[str, Any]] = {}
        seen: set = set()

        # Pre-filter empties / dups while preserving order.
        cleaned: List[Tuple[str, str]] = []
        for ioc_type, value in iocs:
            if not value or not str(value).strip():
                continue
            key = (ioc_type, str(value).strip())
            if key in seen:
                continue
            seen.add(key)
            cleaned.append(key)

        total = len(cleaned)
        for idx, (ioc_type, ioc_value) in enumerate(cleaned, 1):
            print(f"[{idx}/{total}] Checking {ioc_type}: {ioc_value}")
            try:
                if ioc_type == "hash":
                    result = self.check_file_hash(ioc_value)
                elif ioc_type == "ip":
                    result = self.check_ip_address(ioc_value)
                elif ioc_type == "domain":
                    result = self.check_domain(ioc_value)
                elif ioc_type == "url":
                    result = self.check_url(ioc_value)
                else:
                    print(f"  Unsupported IOC type: {ioc_type}")
                    continue

                if result:
                    results[f"{ioc_type}_{ioc_value}"] = result
                    if result.get("malicious", 0) > 0:
                        print(f"  [WARNING] DETECTED: {result['detection_ratio']} engines flag this as malicious")
                    elif result.get("suspicious", 0) > 0:
                        print(f"  [WARNING] SUSPICIOUS: {result['detection_ratio']} engines mark this as suspicious")
                    else:
                        print(f"  [OK] CLEAN: {result.get('detection_ratio', 'N/A')} — no threats")
                else:
                    print(f"  [INFO] No data for {ioc_type}: {ioc_value} "
                          f"(not in VT or analysis pending)")
            except Exception as e:  # never let one bad IOC kill the batch
                print(f"  [ERROR] Failed to check {ioc_type} {ioc_value}: {e}")

        # Persist anything new in cache.
        self._cache.flush()
        return results

    # ── Output ──────────────────────────────────────────────────────────────

    def save_results(
        self, results: Dict[str, Any], filename: str = "virustotal_results.json"
    ) -> None:
        """Save results dict to JSON (atomic write)."""
        try:
            path = Path(filename)
            if path.parent and not path.parent.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            tmp.replace(path)
            print(f"VirusTotal results saved to {filename}")
        except Exception as e:
            print(f"Error saving results: {e}")


# ── Free function (kept for backward compat with analyzer.py) ──────────────


def load_vt_config(config_file: str = "vt_config.json") -> Optional[str]:
    """
    Load VT API key from a config file. Returns the api_key or None.

    Kept as a free function with the same signature as the original.
    Uses utf-8-sig to tolerate an accidental BOM from Notepad/Word.
    """
    try:
        path = Path(config_file)
        if path.exists():
            with open(path, "r", encoding="utf-8-sig") as f:
                config = json.load(f)
            if isinstance(config, dict):
                key = config.get("api_key")
                return key if isinstance(key, str) and key else None
    except (OSError, json.JSONDecodeError) as e:
        print(f"Error loading VirusTotal configuration: {e}")
    return None
