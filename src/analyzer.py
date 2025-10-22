import json
import csv
import os
from json import JSONDecodeError

def load_iocs(filename):  # Function to load Indicators of Compromise (IOCs) from a file
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # Lowercase all IOCs for efficient searchingr
        for key in ['ips', 'domains', 'file_hashes', 'process_names', 'file_paths']:  # For each IOC key
            if key in data:
                data[key] = [v.lower() for v in data[key]]
            else:
                data[key] = []
    except FileNotFoundError:
        print(f"IOC file '{filename}' not found.")
        data = {k: [] for k in ['ips', 'domains', 'file_hashes', 'process_names', 'file_paths']}
    except JSONDecodeError: 
        print(f"IOC file '{filename}' is not valid JSON.")
        data = {k: [] for k in ['ips', 'domains', 'file_hashes', 'process_names', 'file_paths']}
    except Exception as e: 
        print(f"Can't load IOC file: {e}")
        data = {k: [] for k in ['ips', 'domains', 'file_hashes', 'process_names', 'file_paths']}
    return data

def search_iocs(text, iocs):  # Function to search for IOCs in text
    found = []
    text_lower = text.lower() 
    
    for ip in iocs.get('ips', []):  # For each IP in IOCs
        if ip in text:  # If the IP is found in the text (case-sensitive)
            found.append(('ip', ip))  # Add to found list
    
    for d in iocs.get('domains', []):  
        if d in text_lower:
            found.append(('domain', d))
    
    for h in iocs.get('file_hashes', []):
        if h in text_lower: 
            found.append(('hash', h))
    
    for p in iocs.get('process_names', []):
        if p in text_lower: 
            found.append(('process', p))
    
    for path in iocs.get('file_paths', []):
        if path in text_lower:
            found.append(('filepath', path))
    
    return found  # Return the list of found matches

def process_log_file(logfile, iocs, alerts):  # Function to process a log file and search for IOCs
    if not os.path.exists(logfile):  # Check if the log file exists
        print(logfile, "does not exist")
        return
    try:
        with open(logfile, 'r', encoding='utf-8') as f: 
            for line in f:
                line = line.strip()
                results = search_iocs(line, iocs)  # Search for IOCs in the line
                for kind, val in results:
                    alert = {'file': logfile, 'ioc_type': kind, 'pattern': val, 'line': line}  # Create a dictionary with alert info
                    alerts.append(alert)  # Add the alert to the list
                    print("ALERT!", kind, val, line)
    except PermissionError: 
        print(f"Permission denied when opening log file: {logfile}")
    except Exception as e:
        print(f"Error reading log file '{logfile}': {e}")

def save_alerts(alerts, outfile): 
    outdir = os.path.dirname(outfile)
    if outdir and not os.path.exists(outdir):
        print(f"Output directory '{outdir}' does not exist.")
        return
    try:
        with open(outfile, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['file', 'ioc_type', 'pattern', 'line'])  # Create a CSV DictWriter
            writer.writeheader()
            for a in alerts:
                writer.writerow(a)
    except PermissionError:
        print(f"Permission denied when writing to output file: {outfile}")
    except Exception as e:
        print(f"Error writing to output file '{outfile}': {e}")

def main():
    ioc_file = "ioc_list.json" 
    apache_log = "apache.log" 
    output_file = "alerts.csv" 

    iocs = load_iocs(ioc_file) 
    alerts = []  # List to store alerts

    process_log_file(apache_log, iocs, alerts) 

    if alerts:  # If any alerts were found
        print("Found", len(alerts), "alerts")
        save_alerts(alerts, output_file)
        print("Alerts saved to", output_file) 
    else:
        print("No alerts found")

if __name__ == "__main__": 

    main()
