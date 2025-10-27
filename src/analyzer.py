import json
import csv
import os
import argparse
from json import JSONDecodeError
from virustotal_api import VirusTotalAPI, load_vt_config

def load_iocs(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # Lowercase all IOCs for efficient searching
        for key in ['ips', 'domains', 'file_hashes', 'process_names', 'file_paths']:
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
    
    for p in iocs.get('process_names', []):
        if p in text_lower: 
            found.append(('process', p))
    
    for path in iocs.get('file_paths', []):
        if path in text_lower:
            found.append(('filepath', path))
    
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

def save_vt_results_to_csv(vt_results, filename):
    """Save VirusTotal results to CSV file"""
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['ioc_type', 'ioc_value', 'malicious', 'suspicious', 'harmless', 'undetected', 'total_engines', 'detection_ratio', 'reputation'])
            for key, result in vt_results.items():
                writer.writerow([
                    result.get('type', 'unknown'),
                    result.get('hash', result.get('address', result.get('domain', 'unknown'))),
                    result.get('malicious', 0),
                    result.get('suspicious', 0),
                    result.get('harmless', 0),
                    result.get('undetected', 0),
                    result.get('total_engines', 0),
                    result.get('detection_ratio', '0/0'),
                    result.get('reputation', 0)
                ])
    except Exception as e:
        print(f"Error saving VirusTotal results to CSV: {e}")

def save_combined_results(alerts, vt_results, filename):
    """Save combined analysis results to CSV file"""
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['type', 'ioc_type', 'ioc_value', 'malicious', 'suspicious', 'harmless', 'undetected', 'total_engines', 'detection_ratio', 'reputation', 'source_file', 'log_line'])
            
            # Add log analysis results
            for alert in alerts:
                writer.writerow([
                    'log_analysis',
                    alert['ioc_type'],
                    alert['pattern'],
                    0, 0, 0, 0, 0, 'N/A', 0,  # VirusTotal fields (not applicable)
                    alert['file'],
                    alert['line']
                ])
            
            # Add VirusTotal results
            for key, result in vt_results.items():
                writer.writerow([
                    'virustotal_check',
                    result.get('type', 'unknown'),
                    result.get('hash', result.get('address', result.get('domain', 'unknown'))),
                    result.get('malicious', 0),
                    result.get('suspicious', 0),
                    result.get('harmless', 0),
                    result.get('undetected', 0),
                    result.get('total_engines', 0),
                    result.get('detection_ratio', '0/0'),
                    result.get('reputation', 0),
                    'N/A',  # source_file (not applicable)
                    'N/A'   # log_line (not applicable)
                ])
    except Exception as e:
        print(f"Error saving combined results: {e}")

def load_vt_config_file(config_file="vt_config.json"):
    """Load VirusTotal configuration from file"""
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"VirusTotal configuration file '{config_file}' not found.")
        return None
    except Exception as e:
        print(f"Error loading VirusTotal configuration: {e}")
        return None

def check_iocs_with_virustotal(iocs, vt_config):
    """Check found IOCs via VirusTotal API"""
    if not vt_config or not vt_config.get('enable_vt_checks', False):
        print("VirusTotal checks disabled in configuration.")
        return {}
    
    try:
        # Initialize VirusTotal API
        api_key = vt_config.get('api_key') or load_vt_config()
        if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY_HERE":
            print("VirusTotal API key not configured. Skipping VirusTotal checks.")
            return {}
        
        vt_api = VirusTotalAPI(api_key)
        
        # Prepare IOC list for checking
        iocs_to_check = []
        
        if vt_config.get('check_file_hashes', True):
            for hash_val in iocs.get('file_hashes', []):
                if hash_val and hash_val.strip():
                    iocs_to_check.append(('hash', hash_val))
        
        if vt_config.get('check_ip_addresses', True):
            for ip in iocs.get('ips', []):
                if ip and ip.strip():
                    iocs_to_check.append(('ip', ip))
        
        if vt_config.get('check_domains', True):
            for domain in iocs.get('domains', []):
                if domain and domain.strip():
                    iocs_to_check.append(('domain', domain))
        
        if not iocs_to_check:
            print("No IOCs to check via VirusTotal.")
            return {}
        
        print(f"\n=== Checking {len(iocs_to_check)} IOCs via VirusTotal ===")
        vt_results = vt_api.batch_check_iocs(iocs_to_check)
        
        # Save results if enabled in configuration
        if vt_config.get('save_vt_results', True):
            results_file = vt_config.get('vt_results_file', 'virustotal_results.json')
            vt_api.save_results(vt_results, results_file)
        
        return vt_results
        
    except Exception as e:
        print(f"Error checking via VirusTotal: {e}")
        return {}

def show_menu():
    """Display interactive menu"""
    print("\n" + "="*50)
    print("    IOC Log Analyzer with VirusTotal")
    print("="*50)
    print()
    print("1. Log analysis only (fast)")
    print("2. Log analysis + VirusTotal check")
    print("3. VirusTotal IOC check only")
    print("4. Exit")
    print()
    print("="*50)
    
    while True:
        try:
            choice = input("Enter number (1-4): ").strip()
            if choice in ['1', '2', '3', '4']:
                return choice
            else:
                print("Invalid choice. Please enter 1-4.")
        except KeyboardInterrupt:
            print("\nExiting...")
            return '4'


def run_analysis(ioc_file, log_file, output_file, vt_config_file, vt_check, vt_only):
    """Run the analysis with given parameters"""
    
    print("=== IOC Log Analyzer with VirusTotal Integration ===")
    print(f"IOC file: {ioc_file}")
    print(f"Log file: {log_file}")
    print(f"Output file: {output_file}")
    
    # Load IOCs
    iocs = load_iocs(ioc_file)
    print(f"Loaded IOCs: {sum(len(v) for v in iocs.values())} items")
    
    # Load VirusTotal configuration
    vt_config = None
    if vt_check or vt_only:
        vt_config = load_vt_config_file(vt_config_file)
        if vt_config:
            print("VirusTotal configuration loaded")
        else:
            print("Failed to load VirusTotal configuration")
    
    # Check IOCs via VirusTotal if enabled
    vt_results = {}
    if vt_config and (vt_check or vt_only):
        vt_results = check_iocs_with_virustotal(iocs, vt_config)
    
    # Analyze log file if not in "VirusTotal only" mode
    alerts = []
    if not vt_only:
        print(f"\n=== Log file analysis: {log_file} ===")
        process_log_file(log_file, iocs, alerts)
        
        if alerts:
            print(f"Found {len(alerts)} alerts")
        else:
            print("No alerts found")
    else:
        print("Skipping log file analysis (VirusTotal only mode)")
    
    # Output VirusTotal results summary
    if vt_results:
        print(f"\n=== VirusTotal Results Summary ===")
        malicious_count = sum(1 for r in vt_results.values() if r.get('malicious', 0) > 0)
        suspicious_count = sum(1 for r in vt_results.values() if r.get('suspicious', 0) > 0)
        
        print(f"Total checked: {len(vt_results)}")
        print(f"Malicious: {malicious_count}")
        print(f"Suspicious: {suspicious_count}")
        
        if malicious_count > 0 or suspicious_count > 0:
            print("\n[WARNING] THREATS DETECTED:")
            for key, result in vt_results.items():
                if result.get('malicious', 0) > 0:
                    print(f"  [MALICIOUS] {result.get('type', 'unknown')}: {result.get('hash', result.get('address', result.get('domain', 'unknown')))} - {result['detection_ratio']} engines")
                elif result.get('suspicious', 0) > 0:
                    print(f"  [SUSPICIOUS] {result.get('type', 'unknown')}: {result.get('hash', result.get('address', result.get('domain', 'unknown')))} - {result['detection_ratio']} engines")
    
    # Save results based on analysis type
    if vt_check and not vt_only and alerts:
        # Combined analysis: save both log analysis and VirusTotal results in one file
        combined_filename = output_file.replace('.csv', '_combined.csv')
        save_combined_results(alerts, vt_results, combined_filename)
        print(f"Combined results saved to {combined_filename}")
        
        # Also save VirusTotal results separately
        vt_csv_filename = output_file.replace('.csv', '_virustotal.csv')
        save_vt_results_to_csv(vt_results, vt_csv_filename)
        print(f"VirusTotal results saved to {vt_csv_filename}")
        
    elif vt_only and vt_results:
        # VirusTotal only: save VirusTotal results
        vt_csv_filename = output_file.replace('.csv', '_virustotal.csv')
        save_vt_results_to_csv(vt_results, vt_csv_filename)
        print(f"VirusTotal results saved to {vt_csv_filename}")
        
    elif alerts and not vt_check:
        # Log analysis only: save alerts normally
        save_alerts(alerts, output_file)
        print(f"Alerts saved to {output_file}")
    
    print("\n=== Analysis completed ===")

def main():
    """Main function with interactive menu"""
    import sys
    
    # Check if command line arguments are provided
    if len(sys.argv) > 1:
        # Command line mode
        parser = argparse.ArgumentParser(description='IOC Log Analyzer with VirusTotal integration', add_help=False)
        parser.add_argument('--ioc', default='ioc_list.json', help='IOC list file (default: ioc_list.json)')
        parser.add_argument('--log', default='apache.log', help='Log file to analyze (default: apache.log)')
        parser.add_argument('--output', default='alerts.csv', help='Output CSV file (default: alerts.csv)')
        parser.add_argument('--vt-config', default='vt_config.json', help='VirusTotal config file (default: vt_config.json)')
        parser.add_argument('--vt-check', action='store_true', help='Enable VirusTotal checks')
        parser.add_argument('--vt-only', action='store_true', help='Only check IOC list with VirusTotal, skip log analysis')
        
        try:
            args = parser.parse_args()
            run_analysis(args.ioc, args.log, args.output, args.vt_config, args.vt_check, args.vt_only)
        except SystemExit:
            print("Use 'python analyzer.py' for interactive mode or provide valid arguments.")
    else:
        # Interactive mode
        while True:
            choice = show_menu()
            
            if choice == '1':
                # Log analysis only
                print("\n=== Log Analysis Only ===")
                run_analysis('ioc_list.json', 'apache.log', 'alerts.csv', 'vt_config.json', False, False)
                
            elif choice == '2':
                # Log analysis + VirusTotal
                print("\n=== Log Analysis + VirusTotal ===")
                run_analysis('ioc_list.json', 'apache.log', 'alerts.csv', 'vt_config.json', True, False)
                
            elif choice == '3':
                # VirusTotal only
                print("\n=== VirusTotal IOC Check Only ===")
                run_analysis('ioc_list.json', 'apache.log', 'alerts.csv', 'vt_config.json', True, True)
                
            elif choice == '4':
                # Exit
                print("Goodbye!")
                break
            
            # Ask if user wants to continue
            if choice != '4':
                print("\n" + "="*50)
                try:
                    continue_choice = input("Do you want to run another analysis? (y/N): ").strip().lower()
                    if continue_choice != 'y':
                        print("Goodbye!")
                        break
                except (EOFError, KeyboardInterrupt):
                    print("\nGoodbye!")
                    break

if __name__ == "__main__": 
    main()
