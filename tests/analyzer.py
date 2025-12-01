import json
import csv
import os
from json import JSONDecodeError

def load_iocs(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # Lowercase all IOCs for efficient searching (except URLs which should preserve case)
        for key in ['ips', 'domains', 'file_hashes', 'urls']:
            if key in data:
                if key == 'urls':
                    data[key] = [v.strip() for v in data[key] if v.strip()]
                else:
                    data[key] = [v.lower() for v in data[key] if v.strip()]
            else:
                data[key] = []
    except FileNotFoundError:
        print(f"IOC file '{filename}' not found.")
        data = {k: [] for k in ['ips', 'domains', 'file_hashes', 'urls']}
    except JSONDecodeError:
        print(f"IOC file '{filename}' is not valid JSON.")
        data = {k: [] for k in ['ips', 'domains', 'file_hashes', 'urls']}
    except Exception as e:
        print(f"Can't load IOC file: {e}")
        data = {k: [] for k in ['ips', 'domains', 'file_hashes', 'urls']}
    return data

def search_iocs(text, iocs):
    found = []
    text_lower = text.lower()
    
    for ip in iocs.get('ips', []):
        if ip in text:
            found.append(('ip', ip))
    
    for d in iocs.get('domains', []):  
        if d in text_lower:
            found.append(('domain', d))
    
    for h in iocs.get('file_hashes', []):
        if h in text_lower: 
            found.append(('hash', h))
    
    for url in iocs.get('urls', []):
        # Check both original case and lowercase for URL matching
        if url in text or url.lower() in text_lower:
            found.append(('url', url))
    
    return found

def process_log_file(logfile, iocs, alerts):
    if not os.path.exists(logfile):
        print(logfile, "does not exist")
        return
    try:
        with open(logfile, 'r', encoding='utf-8') as f: 
            for line in f:
                line = line.strip()
                results = search_iocs(line, iocs)
                for kind, val in results:
                    alert = {'file': logfile, 'ioc_type': kind, 'pattern': val, 'line': line}
                    alerts.append(alert)
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
            writer = csv.DictWriter(f, fieldnames=['file', 'ioc_type', 'pattern', 'line'])
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
    alerts = []

    process_log_file(apache_log, iocs, alerts)

    if alerts:
        print("Found", len(alerts), "alerts")
        save_alerts(alerts, output_file)
        print("Alerts saved to", output_file)
    else:
        print("No alerts found")

if __name__ == "__main__":
    main()
