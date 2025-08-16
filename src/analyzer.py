import json
import csv
import os
from json import JSONDecodeError

def load_iocs(filename):  # Function to load Indicators of Compromise (IOCs) from a file
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # Lowercase all IOCs for efficient searching
        for key in ['ips', 'domains', 'file_hashes', 'process_names', 'file_paths']:  # For each IOC key
            if key in data:
                data[key] = [v.lower() for v in data[key]]  # Convert all values to lowercase
            else:
                data[key] = []
    except FileNotFoundError:
        print(f"IOC file '{filename}' not found.")
        data = {k: [] for k in ['ips', 'domains', 'file_hashes', 'process_names', 'file_paths']}  # Create empty lists for all keys
    except JSONDecodeError:  # If the file is not valid JSON
        print(f"IOC file '{filename}' is not valid JSON.")  # Print error message
        data = {k: [] for k in ['ips', 'domains', 'file_hashes', 'process_names', 'file_paths']}  # Create empty lists for all keys
    except Exception as e:  # Any other error
        print(f"Can't load IOC file: {e}")
        data = {k: [] for k in ['ips', 'domains', 'file_hashes', 'process_names', 'file_paths']}  # Create empty lists for all keys
    return data  # Return the IOC dictionary

def search_iocs(text, iocs):  # Function to search for IOCs in text
    found = []  # List of found matches
    text_lower = text.lower()  # Convert text to lowercase
    
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
        print(logfile, "does not exist")  # Print error message
        return
    try:
        with open(logfile, 'r', encoding='utf-8') as f: 
            for line in f:
                line = line.strip()  # Remove leading and trailing whitespace
                results = search_iocs(line, iocs)  # Search for IOCs in the line
                for kind, val in results:  # For each found match
                    alert = {'file': logfile, 'ioc_type': kind, 'pattern': val, 'line': line}  # Create a dictionary with alert info
                    alerts.append(alert)  # Add the alert to the list
                    print("ALERT!", kind, val, line)  # Print alert info
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
            writer.writeheader()  # Write the header row
            for a in alerts:
                writer.writerow(a)
    except PermissionError:
        print(f"Permission denied when writing to output file: {outfile}")
    except Exception as e:
        print(f"Error writing to output file '{outfile}': {e}")

def main():
    ioc_file = "ioc_list.json"  # Name of the IOC file
    apache_log = "apache.log"  # Name of the log file
    output_file = "alerts.csv"  # Name of the output file

    iocs = load_iocs(ioc_file)  # Load IOCs from file
    alerts = []  # List to store alerts

    process_log_file(apache_log, iocs, alerts)  # Process the log file

    if alerts:  # If any alerts were found
        print("Found", len(alerts), "alerts")  # Print the number of alerts
        save_alerts(alerts, output_file)  # Save alerts to file
        print("Alerts saved to", output_file)  # Print confirmation
    else:
        print("No alerts found")  # Print if no alerts were found

if __name__ == "__main__": 
    main()