"""
IOC Log Analyzer with VirusTotal Integration - hardened edition.

Backwards-compatible with the original repo:
  * Same CLI:  --ioc, --log, --output, --vt-config, --vt-check, --vt-only
  * Same interactive menu (1/2/3/4)
  * Same public functions for tests:  load_iocs, search_iocs
  * Same JSON config / IOC list / CSV output schemas
  * Same VirusTotalAPI class signature (see virustotal_api.py)

What's new (transparent to existing callers):
  • Robust loaders: bad JSON / wrong types / non-string entries no longer crash.
  • Per-line de-duplication of identical IOC matches.
  • Optional regex auto-extraction of IOCs from log lines (--auto-extract).
  • Persistent VT cache (configured in vt_config.json) survives between runs.
  • Bounded retries with exponential backoff on 429/5xx (no infinite recursion).
  • Atomic CSV/JSON writes; output directory auto-created.
  • Graceful Ctrl+C; explicit exit codes for CI/orchestration.
  • Light ANSI color in TTYs (auto-disabled when piped or on legacy terminals).
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import signal
import sys
from json import JSONDecodeError
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

# Local module — kept compatible with the original layout.
from virustotal_api import VirusTotalAPI, load_vt_config


# ── Console formatting (ANSI, optional) ─────────────────────────────────────

# On Windows, stdout/stderr default to a legacy code page (cp1252 on en-US,
# cp866 on ru-RU, etc.) that can't encode many printable Unicode characters
# we use, like the arrow "→" in normalization messages. This causes
# UnicodeEncodeError crashes on plain `print(...)`. Switch the streams to
# UTF-8 with replacement fallback so we never crash on user-visible output.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # py3.7+
    except (AttributeError, OSError):
        pass

_USE_COLOR = (
    sys.stdout.isatty()
    and os.environ.get("NO_COLOR") is None
    and os.environ.get("TERM", "") != "dumb"
)


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def _safe_print(text: str) -> None:
    """Print, but never crash on encoding errors (Windows legacy code pages)."""
    try:
        print(text)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", "ascii") or "ascii"
        try:
            sys.stdout.buffer.write(text.encode(enc, errors="replace") + b"\n")
            sys.stdout.flush()
        except Exception:
            print(text.encode("ascii", errors="replace").decode("ascii"))


def _info(msg: str) -> None:
    _safe_print(_c("36", "[INFO]") + f" {msg}")


def _ok(msg: str) -> None:
    _safe_print(_c("32", "[OK]") + f" {msg}")


def _warn(msg: str) -> None:
    _safe_print(_c("33", "[WARN]") + f" {msg}")


def _err(msg: str) -> None:
    _safe_print(_c("31", "[ERR]") + f" {msg}")


def _hr(title: str = "") -> None:
    bar = "=" * 50
    if title:
        print(f"\n{bar}\n  {title}\n{bar}")
    else:
        print(bar)


# ── IOC list canonical keys ─────────────────────────────────────────────────

_IOC_KEYS = ("ips", "domains", "file_hashes", "urls")


def _empty_iocs() -> Dict[str, List[str]]:
    return {k: [] for k in _IOC_KEYS}


# Common copy-paste artifacts that need stripping from IOC values:
#   [example.com](http://example.com)   ← markdown auto-link from chat apps / docs
#   <https://evil.com>                  ← angle-bracketed URL (RFC-style)
#   "1.2.3.4"  /  '1.2.3.4'             ← extra quotes around the value
#   defang artifacts: evil[.]com, hxxp://, 1.2.3[.]4
_RE_MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")


def _normalize_ioc_value(value: str, ioc_type: str) -> str:
    """
    Clean a single IOC entry from common copy-paste artifacts so users
    don't have to manually sanitize their IOC list.

    Rules:
      - Markdown auto-link `[label](url)` → use the URL (or label, if it's
        clearly the substantive value).
      - Angle-bracketed `<...>` → strip brackets.
      - Surrounding quotes → strip.
      - Defanged forms: `[.]` → `.`, `(.)` → `.`, `hxxp` → `http`.
      - Whitespace → trim.
    """
    if not isinstance(value, str):
        return ""
    s = value.strip()
    if not s:
        return ""

    # 1) Markdown auto-link.
    m = _RE_MARKDOWN_LINK.match(s)
    if m:
        label, url = m.group(1).strip(), m.group(2).strip()
        # Pick the side that matches the declared type best.
        if ioc_type == "urls":
            s = url or label
        elif ioc_type in ("ips", "domains", "file_hashes"):
            s = label or url
        else:
            s = url or label

    # 2) Angle brackets around URLs / addresses.
    if len(s) >= 2 and s[0] == "<" and s[-1] == ">":
        s = s[1:-1].strip()

    # 3) Quotes baked into the value.
    s = s.strip().strip("'\"").strip()

    # 4) Defanging.
    s = s.replace("[.]", ".").replace("(.)", ".")
    if ioc_type == "urls":
        s = re.sub(r"^hxxps?://", lambda m_: m_.group(0).replace("xx", "tt"), s, flags=re.IGNORECASE)
        s = s.replace("[:]", ":").replace("[/]", "/")

    return s.strip()


# ── Public API for tests: load_iocs / search_iocs ───────────────────────────


def load_iocs(filename: str) -> Dict[str, List[str]]:
    """
    Load an IOC list JSON. Returns a dict with the canonical four keys, each
    mapped to a list of strings.

    The function never raises - it returns empty lists on any failure and
    prints a diagnostic message.
    """
    try:
        with open(filename, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        _err(f"IOC file '{filename}' not found.")
        return _empty_iocs()
    except JSONDecodeError as e:
        _err(f"IOC file '{filename}' is not valid JSON: {e}")
        return _empty_iocs()
    except OSError as e:
        _err(f"Can't load IOC file: {e}")
        return _empty_iocs()

    if not isinstance(raw, dict):
        _err(f"IOC file '{filename}' must contain a JSON object.")
        return _empty_iocs()

    out: Dict[str, List[str]] = _empty_iocs()
    cleaned_count = 0
    for key in _IOC_KEYS:
        vals = raw.get(key, [])
        if not isinstance(vals, list):
            continue
        cleaned: List[str] = []
        for v in vals:
            if not isinstance(v, str):
                continue
            normalized = _normalize_ioc_value(v, key)
            if not normalized:
                continue
            if normalized != v.strip():
                cleaned_count += 1
                _info(f"  IOC normalized: {v!r} → {normalized!r}")
            # URLs preserve case (lookups are case-insensitive in search_iocs);
            # other types are lowercased so list lookups are normalized.
            cleaned.append(normalized if key == "urls" else normalized.lower())
        # Stable de-dup.
        out[key] = list(dict.fromkeys(cleaned))
    if cleaned_count:
        _info(f"  Cleaned {cleaned_count} IOC entries from copy-paste artifacts.")
    return out


def search_iocs(text: str, iocs: Dict[str, Iterable[str]]) -> List[Tuple[str, str]]:
    """
    Match a single text/log-line against an IOC dict.

    Returns a list of (ioc_type, value) tuples, de-duplicated per call.
    Domain matching uses word boundaries to avoid label-substring false
    positives (e.g. "notexample.com" does NOT match "example.com").
    """
    if not isinstance(text, str) or not text:
        return []
    text_lower = text.lower()
    found: List[Tuple[str, str]] = []
    seen: set = set()

    def _add(t: str, v: str) -> None:
        key = (t, v)
        if key not in seen:
            seen.add(key)
            found.append(key)

    for ip in iocs.get("ips", []) or []:
        if not isinstance(ip, str) or not ip:
            continue
        # Boundary-aware match — `1.2.3.4` must NOT match inside `11.2.3.45`.
        # Boundary chars for IPs: a digit or a dot on either side breaks the match.
        if _ip_in_text(ip, text):
            _add("ip", ip)

    for d in iocs.get("domains", []) or []:
        if not isinstance(d, str) or not d:
            continue
        if _domain_in_text(d, text_lower):
            _add("domain", d)

    for h in iocs.get("file_hashes", []) or []:
        if not isinstance(h, str) or not h:
            continue
        if h in text_lower:
            _add("hash", h)

    for url in iocs.get("urls", []) or []:
        if not isinstance(url, str) or not url:
            continue
        if url in text or url.lower() in text_lower:
            _add("url", url)

    return found


def _domain_in_text(domain: str, text_lower: str) -> bool:
    """Boundary-sensitive substring check: a domain label must not be glued
    to other label characters (a-z, 0-9, '-')."""
    if not domain:
        return False
    pattern = r"(?<![a-z0-9-])" + re.escape(domain.lower()) + r"(?![a-z0-9-])"
    return re.search(pattern, text_lower) is not None


def _ip_in_text(ip: str, text: str) -> bool:
    """
    Boundary-sensitive substring check for IPs.

    Without boundaries, `1.2.3.4` matches inside `11.2.3.45` - a classic
    false positive that floods the alerts.

    Boundary rules (asymmetric):
      * LEFT:  preceding char must NOT be a digit or a dot
               (so `11.2.3.4` / `0.1.2.3.4` don't match `1.2.3.4`).
      * RIGHT: following char must NOT be a digit
               (so `1.2.3.40` / `1.2.3.45` don't match,
                but a sentence-ending `1.2.3.4.` still does).
    """
    if not ip:
        return False
    pattern = r"(?<![0-9.])" + re.escape(ip) + r"(?![0-9])"
    return re.search(pattern, text) is not None


# ── Optional regex IOC auto-extraction (opt-in via --auto-extract) ──────────

_RE_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE
)
_RE_URL = re.compile(r"https?://[^\s'\"<>{}|\\^`]+", re.IGNORECASE)
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_PRIVATE_IP_RE = re.compile(
    r"^(?:0\.|10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|"
    r"192\.0\.0\.|192\.0\.2\.|192\.168\.|198\.(?:1[89])\.|198\.51\.100\.|"
    r"203\.0\.113\.|22[4-9]\.|2[3-5]\d\.|255\.)"
)
_URL_TRAILING = ".,;:!?)]}>\"'"

# Things that *look* like domains but are file extensions in URL paths or
# disk paths. Used to suppress false positives in --auto-extract mode.
_FILE_EXT_DENYLIST = frozenset({
    "php", "phtml", "asp", "aspx", "jsp", "cgi", "py", "rb", "pl",
    "html", "htm", "xhtml", "xml", "json", "yaml", "yml", "toml", "ini",
    "css", "scss", "less", "js", "mjs", "ts", "tsx", "jsx", "map",
    "txt", "log", "md", "rst", "csv", "tsv",
    "ico", "jpg", "jpeg", "png", "gif", "bmp", "svg", "webp", "tiff",
    "mp3", "mp4", "avi", "mov", "wav", "ogg", "webm", "mkv", "flv",
    "exe", "dll", "sys", "msi", "bat", "cmd", "sh", "ps1",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt",
    "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "iso",
    "so", "deb", "rpm", "apk", "ipa", "jar", "war", "pkg",
    "conf", "cfg", "lock", "bak", "tmp", "swp", "pid",
    "woff", "woff2", "ttf", "otf", "eot",
    "wasm", "class", "o", "obj", "a", "lib",
})


def _extract_iocs_from_text(text: str) -> List[Tuple[str, str]]:
    """Regex-based IOC auto-extraction. Used only when --auto-extract is set."""
    hits: List[Tuple[str, str]] = []
    seen: set = set()
    url_hosts: set = set()

    def _add(t: str, v: str) -> None:
        if (t, v) in seen:
            return
        seen.add((t, v))
        hits.append((t, v))

    for u in _RE_URL.findall(text):
        clean = u
        while clean and clean[-1] in _URL_TRAILING:
            clean = clean[:-1]
        _add("url", clean)
        try:
            host = urlparse(clean).hostname
            if host:
                url_hosts.add(host.lower())
        except ValueError:
            pass

    for ip in _RE_IP.findall(text):
        if not _PRIVATE_IP_RE.match(ip) and ip not in ("0.0.0.0", "255.255.255.255"):
            _add("ip", ip)

    for d in _RE_DOMAIN.findall(text):
        d_low = d.lower()
        if d_low.replace(".", "").isdigit():
            continue  # avoid catching IPs as domains
        if d_low in url_hosts:
            continue  # already counted as URL
        # File-extension guard: skip 2-label "domains" whose right side is
        # actually a common file extension (wp-admin.php, index.html, ...).
        # Multi-label hostnames (a.b.example.com) are still accepted.
        labels = d_low.split(".")
        if len(labels) == 2 and labels[-1] in _FILE_EXT_DENYLIST:
            continue
        _add("domain", d_low)

    # Match longest hashes first so a SHA256 isn't also flagged as MD5/SHA1.
    found_hashes: List[str] = []
    for pat in (_RE_SHA256, _RE_SHA1, _RE_MD5):
        for h in pat.findall(text):
            hl = h.lower()
            if any(hl in longer for longer in found_hashes):
                continue
            found_hashes.append(hl)
            _add("hash", hl)

    return hits


# ── Log processing ──────────────────────────────────────────────────────────


def process_log_file(
    logfile: str,
    iocs: Dict[str, List[str]],
    alerts: List[Dict[str, str]],
    *,
    auto_extract: bool = False,
    quiet: bool = False,
) -> None:
    """
    Scan a log file line-by-line, appending alerts in-place (kept identical
    to the original so callers don't have to change).
    """
    if not os.path.exists(logfile):
        _err(f"Log file does not exist: {logfile}")
        return

    try:
        with open(logfile, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\r\n")
                # Per-line dedup so the same IOC isn't logged twice.
                seen: set = set()
                for kind, val in search_iocs(line, iocs):
                    if (kind, val) in seen:
                        continue
                    seen.add((kind, val))
                    alert = {
                        "file": logfile,
                        "ioc_type": kind,
                        "pattern": val,
                        "line": line,
                    }
                    alerts.append(alert)
                    if not quiet:
                        print(f"{_c('31', 'ALERT!')} {kind} {val}  {line[:160]}")
                if auto_extract:
                    for kind, val in _extract_iocs_from_text(line):
                        if (kind, val) in seen:
                            continue
                        seen.add((kind, val))
                        alert = {
                            "file": logfile,
                            "ioc_type": kind,
                            "pattern": val,
                            "line": line,
                        }
                        alerts.append(alert)
                        if not quiet:
                            print(f"{_c('33', 'EXTRACT')} {kind} {val}  {line[:160]}")
    except PermissionError:
        _err(f"Permission denied when opening log file: {logfile}")
    except OSError as e:
        _err(f"Error reading log file '{logfile}': {e}")


# ── Atomic CSV / JSON writers ───────────────────────────────────────────────


def _ensure_outdir(path: str) -> bool:
    outdir = os.path.dirname(path)
    if outdir and not os.path.isdir(outdir):
        try:
            os.makedirs(outdir, exist_ok=True)
        except OSError as e:
            _err(f"Cannot create output directory '{outdir}': {e}")
            return False
    return True


def _atomic_write(path: str, text: str) -> bool:
    if not _ensure_outdir(path):
        return False
    p = Path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    try:
        with open(tmp, "w", newline="", encoding="utf-8") as f:
            f.write(text)
        tmp.replace(p)
        return True
    except PermissionError:
        _err(f"Permission denied when writing to: {path}")
    except OSError as e:
        _err(f"Error writing to '{path}': {e}")
    return False


def save_alerts(alerts: List[Dict[str, str]], outfile: str) -> None:
    """Write alerts.csv with the original column set."""
    import io

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["file", "ioc_type", "pattern", "line"])
    writer.writeheader()
    for a in alerts:
        writer.writerow(a)
    if _atomic_write(outfile, buf.getvalue()):
        _ok(f"Alerts saved to {outfile}")


def _ioc_value_from_result(result: Dict[str, Any]) -> str:
    """
    Pick the most user-friendly identifier from a VT result row.

    For files we prefer `queried_hash` - the exact value the user put in
    their IOC list - so a summary line about an MD5 lookup doesn't suddenly
    print VT's canonical SHA-256 (which is the same file but a different
    fingerprint and confuses readers).
    """
    return (
        result.get("queried_hash")
        or result.get("hash")
        or result.get("address")
        or result.get("domain")
        or result.get("url")
        or "unknown"
    )


def save_vt_results_to_csv(vt_results: Dict[str, Dict[str, Any]], filename: str) -> None:
    """
    Write the original VT-only CSV schema, plus a trailing `extra` column
    that carries the canonical SHA-256 for files when it differs from the
    queried hash. The original 9 columns are unchanged so legacy consumers
    still parse fine.
    """
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "ioc_type",
            "ioc_value",
            "malicious",
            "suspicious",
            "harmless",
            "undetected",
            "total_engines",
            "detection_ratio",
            "reputation",
            "extra",
        ]
    )
    for _key, result in vt_results.items():
        extra = ""
        if result.get("type") == "file":
            queried = result.get("queried_hash")
            sha256 = result.get("sha256") or result.get("hash")
            if queried and sha256 and queried != sha256:
                extra = f"sha256={sha256}"
        writer.writerow(
            [
                result.get("type", "unknown"),
                _ioc_value_from_result(result),
                result.get("malicious", 0),
                result.get("suspicious", 0),
                result.get("harmless", 0),
                result.get("undetected", 0),
                result.get("total_engines", 0),
                result.get("detection_ratio", "0/0"),
                result.get("reputation", 0),
                extra,
            ]
        )
    if _atomic_write(filename, buf.getvalue()):
        _ok(f"VirusTotal results saved to {filename}")


def save_combined_results(
    alerts: List[Dict[str, str]],
    vt_results: Dict[str, Dict[str, Any]],
    filename: str,
) -> None:
    """Write the original combined CSV schema."""
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "type",
            "ioc_type",
            "ioc_value",
            "malicious",
            "suspicious",
            "harmless",
            "undetected",
            "total_engines",
            "detection_ratio",
            "reputation",
            "source_file",
            "log_line",
        ]
    )
    for alert in alerts:
        writer.writerow(
            [
                "log_analysis",
                alert.get("ioc_type", ""),
                alert.get("pattern", ""),
                0, 0, 0, 0, 0, "N/A", 0,
                alert.get("file", ""),
                alert.get("line", ""),
            ]
        )
    for _key, result in vt_results.items():
        writer.writerow(
            [
                "virustotal_check",
                result.get("type", "unknown"),
                _ioc_value_from_result(result),
                result.get("malicious", 0),
                result.get("suspicious", 0),
                result.get("harmless", 0),
                result.get("undetected", 0),
                result.get("total_engines", 0),
                result.get("detection_ratio", "0/0"),
                result.get("reputation", 0),
                "N/A",
                "N/A",
            ]
        )
    if _atomic_write(filename, buf.getvalue()):
        _ok(f"Combined results saved to {filename}")


# ── VT config loading ───────────────────────────────────────────────────────

# Default config - used when fields are missing or the file is absent.
_VT_DEFAULTS: Dict[str, Any] = {
    "api_key": "",
    "rate_limit_delay": 1,
    "enable_vt_checks": True,
    "check_file_hashes": True,
    "check_ip_addresses": True,
    "check_domains": True,
    "check_urls": True,
    "save_vt_results": True,
    "vt_results_file": "virustotal_results.json",
    # New (optional) — safe defaults preserve original behavior.
    "cache_enabled": True,
    "cache_path": ".vt_cache.json",
    "cache_ttl_hours": 24,
    "negative_cache_ttl_hours": 4,
    "max_retries": 4,
    "request_timeout": 30,
}


def load_vt_config_file(config_file: str = "vt_config.json") -> Optional[Dict[str, Any]]:
    """Load and merge VT config with defaults. Returns None on missing file."""
    abs_path = os.path.abspath(config_file)
    if not os.path.exists(config_file):
        _err(f"VirusTotal configuration file not found: {abs_path}")
        return None
    try:
        # utf-8-sig tolerates an accidental BOM written by Notepad/Word/etc.
        with open(config_file, "r", encoding="utf-8-sig") as f:
            user = json.load(f)
    except (OSError, JSONDecodeError) as e:
        _err(f"Error loading VirusTotal configuration ({abs_path}): {e}")
        return None
    if not isinstance(user, dict):
        _err(f"'{abs_path}' must contain a JSON object.")
        return None
    merged = dict(_VT_DEFAULTS)
    merged.update({k: v for k, v in user.items() if v is not None})
    # Surface the resolved path so users can spot when the wrong file is read.
    _info(f"Loaded VT config from: {abs_path}")
    raw_key = merged.get("api_key")
    if isinstance(raw_key, str):
        clean = raw_key.strip().strip("'\"").strip()
        if clean and clean.lower() != "your_virustotal_api_key_here":
            _info(f"  api_key: length={len(clean)} "
                  f"first4={clean[:4]!r} last4={clean[-4:]!r}")
        elif clean.lower() == "your_virustotal_api_key_here":
            _warn(f"  api_key: still the placeholder ({clean[:8]}...)")
        else:
            _warn(f"  api_key: empty / whitespace only (raw repr: {raw_key!r})")
    else:
        _warn(f"  api_key: missing or wrong type ({type(raw_key).__name__})")
    return merged


def _resolve_api_key(vt_config: Dict[str, Any]) -> Optional[str]:
    """
    Resolve the VT API key. Order of precedence:
        env var VT_API_KEY  >  vt_config['api_key']  >  load_vt_config('vt_config.json')

    Strips whitespace, treats the placeholder as "not set" case-insensitively,
    and prints a self-diagnostic when nothing usable is found so the user
    can see exactly where we looked.
    """
    placeholder_lower = "your_virustotal_api_key_here"

    def _clean(k: Any) -> Optional[str]:
        if not isinstance(k, str):
            return None
        s = k.strip().strip("'\"").strip()  # tolerate quotes/whitespace from copy-paste
        if not s:
            return None
        if s.lower() == placeholder_lower:
            return None
        return s

    diagnostics: List[str] = []

    env_key = _clean(os.getenv("VT_API_KEY"))
    if env_key:
        return env_key
    diagnostics.append("env var VT_API_KEY: not set or placeholder")

    cfg_raw = vt_config.get("api_key")
    cfg_key = _clean(cfg_raw)
    if cfg_key:
        return cfg_key
    if cfg_raw is None:
        diagnostics.append("vt_config['api_key']: missing key (check JSON field name)")
    elif not isinstance(cfg_raw, str):
        diagnostics.append(f"vt_config['api_key']: wrong type {type(cfg_raw).__name__}")
    elif not cfg_raw.strip():
        diagnostics.append("vt_config['api_key']: empty / whitespace-only")
    else:
        diagnostics.append("vt_config['api_key']: still the placeholder")

    file_key = _clean(load_vt_config())
    if file_key:
        return file_key
    diagnostics.append("load_vt_config('vt_config.json'): nothing usable")

    _warn("Could not find a usable VirusTotal API key:")
    for line in diagnostics:
        print(f"        - {line}")
    _info("Set the key in src/vt_config.json (field 'api_key') "
          "or export VT_API_KEY=... in your environment.")
    return None


def check_iocs_with_virustotal(
    iocs: Dict[str, List[str]], vt_config: Optional[Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    """Drive the VT checks per the original behavior + new caching/backoff."""
    if not vt_config or not vt_config.get("enable_vt_checks", False):
        _info("VirusTotal checks disabled in configuration.")
        return {}

    api_key = _resolve_api_key(vt_config)
    if not api_key:
        _warn("VirusTotal API key not configured. Skipping VirusTotal checks.")
        return {}
    _ok(f"Using VT API key: length={len(api_key)} "
        f"first4={api_key[:4]!r} last4={api_key[-4:]!r}")

    cache_path = vt_config.get("cache_path") or ".vt_cache.json"
    if not vt_config.get("cache_enabled", True):
        cache_path = None  # disables persistent cache

    try:
        vt_api = VirusTotalAPI(
            api_key,
            rate_limit_delay=float(vt_config.get("rate_limit_delay", 1) or 1),
            request_timeout=float(vt_config.get("request_timeout", 30) or 30),
            max_retries=int(vt_config.get("max_retries", 4) or 4),
            cache_path=cache_path,
            cache_ttl_hours=int(vt_config.get("cache_ttl_hours", 24) or 24),
            negative_cache_ttl_hours=int(vt_config.get("negative_cache_ttl_hours", 4) or 4),
        )
    except ValueError as e:
        _err(str(e))
        return {}

    iocs_to_check: List[Tuple[str, str]] = []
    if vt_config.get("check_file_hashes", True):
        for h in iocs.get("file_hashes", []):
            if isinstance(h, str) and h.strip():
                iocs_to_check.append(("hash", h.strip()))
    if vt_config.get("check_ip_addresses", True):
        for ip in iocs.get("ips", []):
            if isinstance(ip, str) and ip.strip():
                iocs_to_check.append(("ip", ip.strip()))
    if vt_config.get("check_domains", True):
        for d in iocs.get("domains", []):
            if isinstance(d, str) and d.strip():
                iocs_to_check.append(("domain", d.strip()))
    if vt_config.get("check_urls", True):
        for u in iocs.get("urls", []):
            if isinstance(u, str) and u.strip():
                iocs_to_check.append(("url", u.strip()))

    if not iocs_to_check:
        _info("No IOCs to check via VirusTotal.")
        vt_api.close()
        return {}

    _hr(f"Checking {len(iocs_to_check)} IOCs via VirusTotal")
    try:
        vt_results = vt_api.batch_check_iocs(iocs_to_check)
    finally:
        vt_api.close()

    if vt_config.get("save_vt_results", True):
        # Re-open just to use the same atomic save_results helper.
        try:
            results_file = vt_config.get("vt_results_file", "virustotal_results.json")
            VirusTotalAPI.__dict__["save_results"](vt_api, vt_results, results_file)  # type: ignore[arg-type]
        except Exception:
            # Fallback: write directly.
            try:
                with open(vt_config.get("vt_results_file", "virustotal_results.json"),
                          "w", encoding="utf-8") as f:
                    json.dump(vt_results, f, ensure_ascii=False, indent=2)
            except OSError as e:
                _err(f"Could not save VT results: {e}")

    return vt_results


# ── Interactive menu ────────────────────────────────────────────────────────


def show_menu() -> str:
    print()
    _hr("    IOC Log Analyzer with VirusTotal")
    print()
    print("  1. Log analysis only (fast)")
    print("  2. Log analysis + VirusTotal check")
    print("  3. VirusTotal IOC check only")
    print("  4. Exit")
    print()
    _hr()

    while True:
        try:
            choice = input("Enter number (1-4): ").strip()
            if choice in {"1", "2", "3", "4"}:
                return choice
            _warn("Invalid choice. Please enter 1, 2, 3, or 4.")
        except (EOFError, KeyboardInterrupt):
            print("\nExiting...")
            return "4"


# ── Run analysis ────────────────────────────────────────────────────────────


def run_analysis(
    ioc_file: str,
    log_file: str,
    output_file: str,
    vt_config_file: str,
    vt_check: bool,
    vt_only: bool,
    *,
    auto_extract: bool = False,
    quiet: bool = False,
) -> int:
    """
    Run the analysis with the given parameters.

    Returns an exit code (0 = ok, 2 = nothing found / nothing checked).
    """
    _hr("IOC Log Analyzer with VirusTotal Integration")
    _info(f"IOC file:    {ioc_file}")
    _info(f"Log file:    {log_file}")
    _info(f"Output file: {output_file}")

    iocs = load_iocs(ioc_file)
    total_iocs = sum(len(v) for v in iocs.values())
    _info(f"Loaded IOCs: {total_iocs} items")

    vt_config: Optional[Dict[str, Any]] = None
    if vt_check or vt_only:
        vt_config = load_vt_config_file(vt_config_file)
        if vt_config:
            _ok("VirusTotal configuration loaded")
        else:
            _err("Failed to load VirusTotal configuration")

    vt_results: Dict[str, Dict[str, Any]] = {}
    if vt_config and (vt_check or vt_only):
        vt_results = check_iocs_with_virustotal(iocs, vt_config)

    alerts: List[Dict[str, str]] = []
    if not vt_only:
        _hr(f"Log file analysis: {log_file}")
        process_log_file(log_file, iocs, alerts, auto_extract=auto_extract, quiet=quiet)
        if alerts:
            _ok(f"Found {len(alerts)} alerts")
        else:
            _info("No alerts found")
    else:
        _info("Skipping log file analysis (VirusTotal-only mode)")

    if vt_results:
        _hr("VirusTotal Results Summary")
        malicious_count = sum(1 for r in vt_results.values() if r.get("malicious", 0) > 0)
        suspicious_count = sum(1 for r in vt_results.values() if r.get("suspicious", 0) > 0)
        print(f"Total checked: {len(vt_results)}")
        print(f"Malicious:     {_c('31', str(malicious_count))}")
        print(f"Suspicious:    {_c('33', str(suspicious_count))}")
        if malicious_count or suspicious_count:
            print(f"\n{_c('31', '[WARNING] THREATS DETECTED:')}")
            for _, result in vt_results.items():
                ioc_value = _ioc_value_from_result(result)
                # When VT returned a different (canonical SHA-256) hash than
                # what the user queried, surface both so the report stays
                # traceable to the user's IOC list.
                extra = ""
                if result.get("type") == "file":
                    queried = result.get("queried_hash")
                    sha256 = result.get("sha256") or result.get("hash")
                    if queried and sha256 and queried != sha256:
                        extra = f"  (sha256: {sha256})"
                if result.get("malicious", 0) > 0:
                    print(
                        f"  {_c('31', '[MALICIOUS]')} {result.get('type', 'unknown')}: "
                        f"{ioc_value} — {result.get('detection_ratio', 'N/A')} engines{extra}"
                    )
                elif result.get("suspicious", 0) > 0:
                    print(
                        f"  {_c('33', '[SUSPICIOUS]')} {result.get('type', 'unknown')}: "
                        f"{ioc_value} — {result.get('detection_ratio', 'N/A')} engines{extra}"
                    )

    # Save outputs (same paths as original)
    base_name = os.path.splitext(output_file)[0]
    if vt_check and not vt_only:
        if alerts and vt_results:
            save_combined_results(alerts, vt_results, f"{base_name}_combined.csv")
        if vt_results:
            save_vt_results_to_csv(vt_results, f"{base_name}_virustotal.csv")
        if alerts:
            save_alerts(alerts, output_file)
    elif vt_only and vt_results:
        save_vt_results_to_csv(vt_results, f"{base_name}_virustotal.csv")
    elif alerts and not vt_check:
        save_alerts(alerts, output_file)

    _hr("Analysis completed")

    # Exit code: 0 if we did something useful, 2 otherwise.
    return 0 if (alerts or vt_results) else 2


# ── Diagnostics ─────────────────────────────────────────────────────────────


def _diagnose(config_file: str) -> int:
    """
    Self-diagnose VT config + API-key resolution. Prints exactly what the
    analyzer sees, then returns 0 (key OK) or 1 (problem found).
    """
    _hr("VT Config Diagnosis")
    print(f"  CWD:                       {os.getcwd()}")
    print(f"  Looking for config at:     {os.path.abspath(config_file)}")

    if not os.path.exists(config_file):
        _err("File does not exist at this path.")
        try:
            entries = sorted(os.listdir("."))[:30]
            print("  Files in current directory:")
            for e in entries:
                print(f"    {e}")
        except OSError:
            pass
        return 1

    try:
        raw = Path(config_file).read_bytes()
    except OSError as e:
        _err(f"Can't read file: {e}")
        return 1
    print(f"  File size:                 {len(raw)} bytes")

    if raw.startswith(b"\xef\xbb\xbf"):
        _warn("File has UTF-8 BOM (Notepad-style). Loaders here tolerate it, "
              "but other tools may break. Consider re-saving as plain UTF-8.")
    elif raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        _err("File appears to be UTF-16. Re-save as UTF-8.")
        return 1

    try:
        parsed = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, JSONDecodeError) as e:
        _err(f"JSON parse error: {e}")
        print("  Hint: check for smart quotes, trailing commas, "
              "or paste artifacts.")
        return 1

    if not isinstance(parsed, dict):
        _err(f"Top-level JSON must be an object, got {type(parsed).__name__}.")
        return 1
    print(f"  JSON keys present:         {sorted(parsed.keys())}")

    if "api_key" not in parsed:
        _err("No 'api_key' field in the JSON.")
        candidates = [k for k in parsed if "key" in k.lower() or "api" in k.lower()]
        if candidates:
            _warn(f"Did you mean: {candidates}? Rename to exactly 'api_key'.")
        return 1

    raw_key = parsed["api_key"]
    print(f"  api_key type:              {type(raw_key).__name__}")
    if isinstance(raw_key, str):
        print(f"  api_key raw repr:          {raw_key!r}")
        print(f"  api_key length (raw):      {len(raw_key)}")
        cleaned = raw_key.strip().strip("'\"").strip()
        print(f"  api_key length (cleaned):  {len(cleaned)}")
        if cleaned and cleaned.lower() != "your_virustotal_api_key_here":
            print(f"  api_key fingerprint:       first4={cleaned[:4]!r} "
                  f"last4={cleaned[-4:]!r}")

    cfg = load_vt_config_file(config_file)
    if cfg is None:
        _err("load_vt_config_file returned None — see errors above.")
        return 1

    resolved = _resolve_api_key(cfg)
    if resolved:
        _ok(f"API key resolved successfully.")
        _ok("VT mode should now work. Run with --vt-check or --vt-only.")
        return 0
    else:
        _err("API key NOT resolved. See diagnostic above.")
        return 1


# ── CLI ─────────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analyzer",
        description="IOC Log Analyzer with VirusTotal integration",
    )
    p.add_argument("--ioc",        default="ioc_list.json", help="IOC list file (default: ioc_list.json)")
    p.add_argument("--log",        default="apache.log",    help="Log file to analyze (default: apache.log)")
    p.add_argument("--output",     default="alerts.csv",    help="Output CSV file (default: alerts.csv)")
    p.add_argument("--vt-config",  default="vt_config.json", help="VirusTotal config file (default: vt_config.json)")
    p.add_argument("--vt-check",   action="store_true",     help="Enable VirusTotal checks")
    p.add_argument("--vt-only",    action="store_true",     help="Only check IOC list with VirusTotal, skip log analysis")
    # New, opt-in extras (no impact when not used).
    p.add_argument("--auto-extract", action="store_true",   help="Also extract IOCs from log lines via regex")
    p.add_argument("--quiet", "-q",  action="store_true",   help="Suppress per-line alert prints")
    p.add_argument("--diagnose",     action="store_true",   help="Diagnose VT config + key, then exit (no analysis)")
    return p


def main() -> int:
    """Main entry point — interactive menu when no args, CLI when args given."""
    # Make Ctrl+C exit cleanly with code 130.
    def _sigint_handler(signum, frame):  # noqa: ARG001
        print("\nInterrupted.")
        sys.exit(130)
    signal.signal(signal.SIGINT, _sigint_handler)

    if len(sys.argv) > 1:
        try:
            args = _build_parser().parse_args()
        except SystemExit as e:
            # argparse prints its own usage text; just propagate.
            return int(e.code or 2)
        if args.diagnose:
            return _diagnose(args.vt_config)
        return run_analysis(
            args.ioc,
            args.log,
            args.output,
            args.vt_config,
            args.vt_check,
            args.vt_only,
            auto_extract=args.auto_extract,
            quiet=args.quiet,
        )

    # Interactive mode.
    while True:
        choice = show_menu()
        if choice == "4":
            print("Goodbye!")
            return 0
        if choice == "1":
            _hr("Log Analysis Only")
            run_analysis("ioc_list.json", "apache.log", "alerts.csv",
                         "vt_config.json", False, False)
        elif choice == "2":
            _hr("Log Analysis + VirusTotal")
            run_analysis("ioc_list.json", "apache.log", "alerts.csv",
                         "vt_config.json", True, False)
        elif choice == "3":
            _hr("VirusTotal IOC Check Only")
            run_analysis("ioc_list.json", "apache.log", "alerts.csv",
                         "vt_config.json", True, True)

        try:
            again = input("\nRun another analysis? (y/N): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            return 0
        if again != "y":
            print("Goodbye!")
            return 0


if __name__ == "__main__":
    sys.exit(main())
