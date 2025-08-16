# IOC Log Analyzer

* A simple Python tool for scanning log files against a list of Indicators of Compromise (IOCs).
Matches are printed to the console and saved into a CSV file for further analysis.

# Features

* Detects IOCs in log files: IP addresses, domains, file hashes, process names, and file paths.

* Saves all findings to alerts.csv in a structured format.

* Easy to configure and extend with your own IOC lists.

# Project Structure

* analyzer.py — main script for scanning logs.

* ioc_list.json — customizable IOC list (edit this file to add your own IOCs).

* A sample log file is not included. Provide your own log when running the script.

# Usage

* Place ioc_list.json and your log file (e.g., apache.log) in the same directory as the script.

# Run:

* python analyzer.py --apache apache.log


* Results will be shown in the console and written to alerts.csv.

# Example CSV output:

file,ioc_type,pattern,line
apache.log,ip,8.8.8.8,"8.8.8.8 - - [22/Jun/2025:14:15:25 +0000] ..."

# Notes

* The script scans for all IOC types in one run.

* IP addresses are matched exactly; all other IOCs are matched case-insensitively.

* If the IOC file or log file is missing, an error will be displayed.

* Alerts are only saved if the output directory exists.

# Requirements

* Python 3.x

* Standard libraries only: json, csv, os

# Example Run
python analyzer.py --apache apache.log

* Example Output
ALERT! ip 8.8.8.8 8.8.8.8 - - [22/Jun/2025:14:15:25 +0000] "GET /about.html HTTP/1.1" 200 890
Found 5 alerts
Alerts saved to alerts.csv


---
