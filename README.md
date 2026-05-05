<img width="1920" height="1040" alt="ioc analyzer" src="https://github.com/user-attachments/assets/4c7bff45-bbb9-4fea-a054-297d901fb389" />

# IOC Log Analyzer with VirusTotal Integration

A Python tool that scans log files for Indicators of Compromise (IOCs) and
optionally enriches them with the VirusTotal API. Matches print to the console
and are saved as CSV (and JSON for VirusTotal results).

## Features

- Finds IOCs in logs: IPs, domains, file hashes (MD5/SHA1/SHA256), and URLs.
- VirusTotal enrichment for hashes, IPs, domains, and URLs.
- **Persistent VirusTotal cache** (positive + negative TTL) - survives between
  runs, dramatically faster on the 4 req/min free tier.
- **Bounded retries with exponential backoff** on 429 / 5xx / network errors;
  honors `Retry-After`.
- **Word-boundary domain matching** - no more false positives from substring
  hits (e.g. `notexample.com` no longer matches `example.com`).
- **Optional regex auto-extraction** of IOCs from log lines (`--auto-extract`).
- Atomic CSV/JSON writes; output directory auto-created.
- Graceful Ctrl+C, sane exit codes, ANSI colors when running in a TTY.

## Project Structure

```
.
├── src/
│   ├── analyzer.py             # main script + interactive menu + CLI
│   ├── virustotal_api.py       # VirusTotal v3 client (cached, retrying)
│   ├── ioc_list.json           # your IOC list (edit this)
│   ├── vt_config.json          # local config (gitignored - copy from example)
│   ├── start_analyzer.cmd      # Windows launcher
│   └── start_analyzer.sh       # Linux/macOS launcher
├── tests/
│   ├── test_analyzer.py
│   ├── apache.log              # sample log
│   └── ioc_list.json           # sample IOCs
├── docs/
│   └── usage.md
├── vt_config.example.json      # template (no secret)
├── requirements.txt
├── LICENSE
└── README.md
```

## Installation

```bash
pip install -r requirements.txt
```

Only requirement: `requests`.

### Configure VirusTotal

```bash
cp vt_config.example.json src/vt_config.json
```

Edit `src/vt_config.json` and set `api_key`, **or** set the `VT_API_KEY`
environment variable (env wins over the file).

## Usage

### Interactive mode (recommended)

```bash
cd src
python analyzer.py
```

Pick from the menu:

```
1. Log analysis only (fast)
2. Log analysis + VirusTotal check
3. VirusTotal IOC check only
4. Exit
```

### Windows launcher

```bat
cd src
start_analyzer.cmd
```

### Linux / macOS launcher

```bash
cd src
chmod +x start_analyzer.sh
./start_analyzer.sh
```

### CLI mode

```bash
# Log analysis only
python analyzer.py --log apache.log --ioc ioc_list.json

# With VirusTotal
python analyzer.py --log apache.log --ioc ioc_list.json \
    --vt-config vt_config.json --vt-check

# VirusTotal only
python analyzer.py --ioc ioc_list.json --vt-config vt_config.json --vt-only

# With regex auto-extraction (also catches IOCs not in your list)
python analyzer.py --log apache.log --ioc ioc_list.json --auto-extract
```

### Command-line options

| Flag | Default | Description |
|---|---|---|
| `--log` | `apache.log` | Log file to analyze |
| `--ioc` | `ioc_list.json` | IOC list file |
| `--output` | `alerts.csv` | Base output path |
| `--vt-config` | `vt_config.json` | VirusTotal config file |
| `--vt-check` | - | Enable VirusTotal enrichment |
| `--vt-only` | / | Skip log analysis; only check the IOC list with VT |
| `--auto-extract` | - | Also extract IOCs from log lines via regex |
| `-q`, `--quiet` | - | Suppress per-line alert prints |

Exit codes: `0` ok, `2` nothing found / nothing checked, `130` interrupted
(Ctrl+C), `1` fatal error.

## VirusTotal Configuration

`src/vt_config.json` - full schema:

```json
{
  "api_key": "YOUR_VIRUSTOTAL_API_KEY_HERE",
  "rate_limit_delay": 1,
  "enable_vt_checks": true,
  "check_file_hashes": true,
  "check_ip_addresses": true,
  "check_domains": true,
  "check_urls": true,
  "save_vt_results": true,
  "vt_results_file": "virustotal_results.json",

  "cache_enabled": true,
  "cache_path": ".vt_cache.json",
  "cache_ttl_hours": 24,
  "negative_cache_ttl_hours": 4,

  "max_retries": 4,
  "request_timeout": 30
}
```

The cache + retry fields are **optional** - defaults are sensible if you omit
them.

## Output Files

- `alerts.csv` - IOC matches in logs (columns: `file, ioc_type, pattern, line`).
- `alerts_combined.csv` - log + VirusTotal results unified.
- `alerts_virustotal.csv` - VirusTotal results only.
- `virustotal_results.json` - raw VirusTotal results dict.
- `.vt_cache.json` - persistent cache (gitignored).

## Sample Output

```
==================================================
  IOC Log Analyzer with VirusTotal Integration
==================================================
[INFO] IOC file:    ioc_list.json
[INFO] Log file:    apache.log
[INFO] Output file: alerts.csv
[INFO] Loaded IOCs: 5 items

==================================================
  Log file analysis: apache.log
==================================================
ALERT! ip 8.8.8.8  8.8.8.8 - - [22/Jun/2025:14:15:25 +0000] "GET /about.html ..."
[OK] Found 5 alerts
[OK] Alerts saved to alerts.csv
```

## Adding Your Own IOCs

Edit `src/ioc_list.json`:

```json
{
  "ips":         ["1.2.3.4", "192.0.2.10"],
  "domains":     ["evil.example", "bad-site.org"],
  "file_hashes": ["44d88612fea8a8f36de82e1278abb02f"],
  "urls":        ["http://evil.example/payload"]
}
```

## Run the tests

```bash
python -m unittest discover -s tests -v
```

## Notes

- IPs are matched as exact substrings; domains use word-boundary matching;
  hashes and URLs are matched case-insensitively.
- VirusTotal free tier is 4 requests/minute - the persistent cache means
  repeat runs only re-query IOCs that have expired or were missing.
- Sensitive files (`vt_config.json`, `virustotal_results.json`,
  `.vt_cache.json`) are gitignored by default.
