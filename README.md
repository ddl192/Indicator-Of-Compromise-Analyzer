
![IOC ANALYZER](https://github.com/user-attachments/assets/cd56bb98-cb54-49a9-b787-e34b568df5ea)

# IOC Log Analyzer with VirusTotal Integration

### A Python tool that scans log files for Indicators of Compromise (IOCs).
* It can also check IOCs with the VirusTotal API.
* Matches appear in the console and are saved to a CSV file.

# Features

* Finds IOCs in logs: IPs, domains, file hashes, and URLs

* VirusTotal integration for live threat checks

* Checks hashes, IPs, domains, and URLs on VirusTotal

* Saves results to alerts.csv

# Configurable checks and detailed VirusTotal info

* Easy to extend with your own IOC lists

# Project Structure

* analyzer.py - main script with VirusTotal integration

* virustotal_api.py - VirusTotal API client
  
* vt_config.example.json - config template (copy and edit with your API key)

* ioc_list.json - list of IOCs (you can edit it)

* requirements.txt - Python dependencies

### Note: bring your own log file when running the script.

# Installation

### Install dependencies

* pip install -r requirements.txt


### Get a VirusTotal API key
* Register at virustotal.com
* and copy your key

### Configure VirusTotal

* cp vt_config.example.json src/vt_config.json


* Edit src/vt_config.json and add your API key
* Or set it as an environment variable VT_API_KEY

# Usage
### Interactive Mode (recommended)
```
cd src
python analyzer.py
```

### Select from the menu:
```
Log analysis only

Log analysis + VirusTotal check

VirusTotal check only

Exit
```
# Windows

### Run start_analyzer.cmd in the src folder.

# Linux or macOS
```
cd src
chmod +x start_analyzer.sh
./start_analyzer.sh
```

# Manual Commands
### Log analysis only
```
cd src
python analyzer.py --log apache.log --ioc ioc_list.json
```
### With VirusTotal
```
cd src
python analyzer.py --log apache.log --ioc ioc_list.json --vt-config vt_config.json --vt-check
```
### VirusTotal only
```
cd src
python analyzer.py --ioc ioc_list.json --vt-config vt_config.json --vt-only
```
### Command Line Options

* --log log file (default: apache.log)

* --ioc IOC list (default: ioc_list.json)

* --output CSV output (default: alerts.csv)

* --vt-config VirusTotal config (default: vt_config.json)

* --vt-check enable VirusTotal checks

* --vt-only run VirusTotal only

# VirusTotal Configuration

* Edit vt_config.json
```
{
  "api_key": "YOUR_VIRUSTOTAL_API_KEY_HERE",
  "rate_limit_delay": 1,
  "enable_vt_checks": true,
  "check_file_hashes": true,
  "check_ip_addresses": true,
  "check_domains": true,
  "check_urls": true,
  "save_vt_results": true,
  "vt_results_file": "virustotal_results.json"
}
```

### Example Output
```
Log Analysis
=== IOC Log Analyzer with VirusTotal Integration ===
IOC file: ioc_list.json
Log file: apache.log

Found 5 alerts
Alerts saved to alerts.csv
```
```
VirusTotal Integration
Checking hash: fb25dd6d01b1fd4f826521377737a37e
[WARNING] DETECTED: 34/75 engines consider it malicious
Results Summary
Total checked: 2
Malicious: 2
Suspicious: 0

Output Files
```

### Combined Analysis

* results_combined.csv - log + VirusTotal results

* results_virustotal.csv - VirusTotal only

### Log Only

* alerts.csv - log analysis results

# Requirements

* Python 3

* requests (install with pip install -r requirements.txt)

# Notes

* Scans all IOC types in one run

* IPs are matched exactly, others case-insensitive

* Free VirusTotal tier allows 4 requests per minute

* VirusTotal results are saved in JSON

* If files are missing, the script shows an error
