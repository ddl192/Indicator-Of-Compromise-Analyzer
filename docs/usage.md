
![USAGE](https://github.com/user-attachments/assets/a723a6b0-d35d-43ed-bfca-7e661f4c3dfa)

# How to use the analyzer

* Make sure Python 3 is installed

# Install dependencies:

* pip install -r requirements.txt


# Configure VirusTotal (optional):
```
cp vt_config.example.json src/vt_config.json
```
### Edit src/vt_config.json and add your VirusTotal API key


# Run the analyzer

### Windows:
```
cd src
python analyzer.py
# or
start_analyzer.cmd
```

### Linux/macOS:
```
cd src
python3 analyzer.py
# or
chmod +x start_analyzer.sh
./start_analyzer.sh
```

### Pick from the menu:

* Log analysis only

* Log analysis plus VirusTotal check

* VirusTotal IOC check only

* Exit

# Command Line Usage

* Basic Log Analysis

### Windows:
```
cd src
python analyzer.py --log apache.log --ioc ioc_list.json --output results.csv
```

### Linux/macOS:
```
cd src
python3 analyzer.py --log apache.log --ioc ioc_list.json --output results.csv
```

* Combined Analysis (Log plus VirusTotal)

### Windows:
```
cd src
python analyzer.py --log apache.log --ioc ioc_list.json --vt-check --output results.csv
```

### Linux/macOS:
```
cd src
python3 analyzer.py --log apache.log --ioc ioc_list.json --vt-check --output results.csv
```

# Output files created:

* results_combined.csv — unified results

* results_virustotal.csv — VirusTotal results only

* VirusTotal Only

### Windows:
```
cd src
python analyzer.py --ioc ioc_list.json --vt-only --output results.csv
```

### Linux/macOS:
```
cd src
python3 analyzer.py --ioc ioc_list.json --vt-only --output results.csv
```

### Output file created:

* results_virustotal.csv — VirusTotal results only

# Project Contents

* src/analyzer.py — main code for scanning logs

* src/ioc_list.json — list of Indicators of Compromise

* src/apache.log — sample log file

### Output files:

* alerts.csv — basic log analysis

* results_combined.csv — log plus VirusTotal

* results_virustotal.csv — VirusTotal only

* Tests in tests/test_analyzer.py

* Manual in docs/usage.md

* General info in README.md

# Adding Your Own IOCs

### Open src/ioc_list.json in any editor

* Add IPs, domains, hashes, and URLs

* Save the file

### Example:
```
{
  "ips": ["1.2.3.4", "192.168.1.100"],
  "domains": ["malicious.com", "bad-site.org"],
  "file_hashes": ["abc123def456", "44d88612fea8a8f36de82e1278abb02f"],
  "urls": ["http://malicious.com/payload", "https://bad-site.org/exploit"]
}
```

### Test your changes:
```
cd tests
python test_analyzer.py
```
# Command Line Options

### Basic log analysis
```
python analyzer.py --log apache.log --ioc ioc_list.json --output results.csv
```
### Log plus VirusTotal
```
python analyzer.py --log apache.log --ioc ioc_list.json --vt-check --output full_analysis.csv
```

### VirusTotal only
```
python analyzer.py --ioc ioc_list.json --vt-only
```
# Tips

* The analyzer prints alerts to the terminal and saves them to CSV

* Use interactive mode for easier operation

* Add a VirusTotal API key to enable threat intelligence features
