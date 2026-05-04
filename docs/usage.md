
![USAGE](https://github.com/user-attachments/assets/a723a6b0-d35d-43ed-bfca-7e661f4c3dfa)

# How to use the analyzer

## 1. Setup

You need Python 3.8+ and the `requests` package.

```bash
pip install -r requirements.txt
```

## 2. Configure VirusTotal (optional but recommended)

```bash
cp vt_config.example.json src/vt_config.json
```

Edit `src/vt_config.json` and add your VirusTotal API key — **or** export it
as an environment variable (the env var wins over the file):

```bash
# Linux / macOS
export VT_API_KEY="..."

# Windows (cmd)
set VT_API_KEY=...

# Windows (PowerShell)
$env:VT_API_KEY = "..."
```

## 3. Run the analyzer

### Interactive

```bash
# Linux / macOS
cd src
python3 analyzer.py
# or
chmod +x start_analyzer.sh
./start_analyzer.sh

# Windows
cd src
python analyzer.py
# or
start_analyzer.cmd
```

Pick from the menu:

1. Log analysis only
2. Log analysis + VirusTotal check
3. VirusTotal IOC check only
4. Exit

### Command line

```bash
# Basic log analysis
python analyzer.py --log apache.log --ioc ioc_list.json --output results.csv

# Log + VirusTotal
python analyzer.py --log apache.log --ioc ioc_list.json \
    --vt-config vt_config.json --vt-check --output results.csv

# VirusTotal only
python analyzer.py --ioc ioc_list.json --vt-config vt_config.json --vt-only

# With regex auto-extraction (catches IOCs even if not in your list)
python analyzer.py --log apache.log --ioc ioc_list.json --auto-extract
```

## 4. Output files

| File | Created when | Purpose |
|---|---|---|
| `alerts.csv` | log analysis runs | IOCs matched in logs |
| `combined.csv` | log + VT mode | Unified rows |
| `virustotal.csv` | VT runs | VT-only rows |
| `virustotal_results.json` | VT runs (if `save_vt_results: true`) | Raw VT dict |
| `.vt_cache.json` | VT runs (if `cache_enabled: true`) | Persistent cache (gitignored) |


## 5. Adding IOCs

Open `src/ioc_list.json`:

```json
{
  "ips":         ["1.2.3.4", "192.0.2.10"],
  "domains":     ["evil.example", "bad-site.org"],
  "file_hashes": ["44d88612fea8a8f36de82e1278abb02f"],
  "urls":        ["http://evil.example/payload"]
}
```

Notes:

- Domains are matched on label boundaries — `notexample.com` does NOT match
  `example.com`.
- Hashes are case-insensitive (input is lowercased on load).
- URLs preserve their original case in output but are matched
  case-insensitively.

## 6. Testing

```bash
python -m unittest discover -s tests -v
```

You should see all tests passing. The original tests (`test_load_iocs`,
`test_search_iocs`, `test_search_urls`) still pass unchanged; the suite has
been extended with robustness tests (bad JSON, non-string entries,
word-boundary matching, regex auto-extraction, atomic writes, etc.).

## 7. Tips

- **Free VT tier = 4 req/min.** The persistent cache means repeat runs only
  re-query expired or previously-missing IOCs. With cache enabled, a list of
  100 IOCs that's been queried once will return instantly on the next run.
- **`--auto-extract`** is great when triaging a noisy log: it pulls every
  public IP, domain, hash, and URL out of the lines on top of matching your
  known-bad list. Combine with `--vt-check` to enrich them.
- **CI / scripting:** use the exit codes — `0` for "found something",
  `2` for "nothing found", `130` for Ctrl+C, `1` for fatal errors.
