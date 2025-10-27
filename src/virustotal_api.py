import requests
import time
import json
import os
from typing import Dict, List, Optional, Tuple

class VirusTotalAPI:
    """
    VirusTotal API v3 client class
    """
    
    def __init__(self, api_key: str = None):
        """
        Initialize VirusTotal API client
        
        Args:
            api_key: VirusTotal API key. If not provided, will be loaded from VT_API_KEY environment variable
        """
        self.api_key = api_key or os.getenv('VT_API_KEY')
        if not self.api_key:
            raise ValueError("VirusTotal API key not found. Set VT_API_KEY environment variable or pass key to constructor.")
        
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/json"
        }
        self.rate_limit_delay = 1  # Delay between requests in seconds
    
    def _make_request(self, endpoint: str, params: Dict = None) -> Optional[Dict]:
        """
        Make request to VirusTotal API with error handling
        
        Args:
            endpoint: API endpoint
            params: Request parameters
            
        Returns:
            API response or None on error
        """
        url = f"{self.base_url}/{endpoint}"
        
        try:
            response = requests.get(url, headers=self.headers, params=params)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                print("Rate limit exceeded. Waiting...")
                time.sleep(60)  # Wait one minute when rate limit exceeded
                return self._make_request(endpoint, params)
            elif response.status_code == 403:
                print("Authorization error. Check API key.")
                return None
            else:
                print(f"API error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"Network error: {e}")
            return None
    
    def check_file_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Check file hash in VirusTotal
        
        Args:
            file_hash: SHA256, SHA1 or MD5 file hash
            
        Returns:
            Check result or None
        """
        endpoint = f"files/{file_hash}"
        result = self._make_request(endpoint)
        
        if result and 'data' in result:
            time.sleep(self.rate_limit_delay)
            return self._parse_file_result(result['data'])
        
        return None
    
    def check_ip_address(self, ip_address: str) -> Optional[Dict]:
        """
        Check IP address in VirusTotal
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Check result or None
        """
        endpoint = f"ip_addresses/{ip_address}"
        result = self._make_request(endpoint)
        
        if result and 'data' in result:
            time.sleep(self.rate_limit_delay)
            return self._parse_ip_result(result['data'])
        
        return None
    
    def check_domain(self, domain: str) -> Optional[Dict]:
        """
        Check domain in VirusTotal
        
        Args:
            domain: Domain to check
            
        Returns:
            Check result or None
        """
        endpoint = f"domains/{domain}"
        result = self._make_request(endpoint)
        
        if result and 'data' in result:
            time.sleep(self.rate_limit_delay)
            return self._parse_domain_result(result['data'])
        
        return None
    
    def _parse_file_result(self, data: Dict) -> Dict:
        """
        Parse file check result
        
        Args:
            data: API response data
            
        Returns:
            Processed result
        """
        stats = data.get('attributes', {}).get('last_analysis_stats', {})
        reputation = data.get('attributes', {}).get('reputation', 0)
        
        total_engines = sum(stats.values())
        return {
            'type': 'file',
            'hash': data.get('id'),
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
            'harmless': stats.get('harmless', 0),
            'reputation': reputation,
            'total_engines': total_engines,
            'detection_ratio': f"{stats.get('malicious', 0)}/{total_engines}" if total_engines > 0 else "0/0"
        }
    
    def _parse_ip_result(self, data: Dict) -> Dict:
        """
        Parse IP address check result
        
        Args:
            data: API response data
            
        Returns:
            Processed result
        """
        stats = data.get('attributes', {}).get('last_analysis_stats', {})
        reputation = data.get('attributes', {}).get('reputation', 0)
        
        total_engines = sum(stats.values())
        return {
            'type': 'ip',
            'address': data.get('id'),
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
            'harmless': stats.get('harmless', 0),
            'reputation': reputation,
            'total_engines': total_engines,
            'detection_ratio': f"{stats.get('malicious', 0)}/{total_engines}" if total_engines > 0 else "0/0"
        }
    
    def _parse_domain_result(self, data: Dict) -> Dict:
        """
        Parse domain check result
        
        Args:
            data: API response data
            
        Returns:
            Processed result
        """
        stats = data.get('attributes', {}).get('last_analysis_stats', {})
        reputation = data.get('attributes', {}).get('reputation', 0)
        
        total_engines = sum(stats.values())
        return {
            'type': 'domain',
            'domain': data.get('id'),
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
            'harmless': stats.get('harmless', 0),
            'reputation': reputation,
            'total_engines': total_engines,
            'detection_ratio': f"{stats.get('malicious', 0)}/{total_engines}" if total_engines > 0 else "0/0"
        }
    
    def batch_check_iocs(self, iocs: List[Tuple[str, str]]) -> Dict[str, Dict]:
        """
        Check list of IOCs in VirusTotal
        
        Args:
            iocs: List of tuples (ioc_type, value)
            
        Returns:
            Dictionary with check results
        """
        results = {}
        
        for ioc_type, ioc_value in iocs:
            if not ioc_value or ioc_value.strip() == "":
                continue
                
            print(f"Checking {ioc_type}: {ioc_value}")
            
            try:
                if ioc_type == 'hash':
                    result = self.check_file_hash(ioc_value)
                elif ioc_type == 'ip':
                    result = self.check_ip_address(ioc_value)
                elif ioc_type == 'domain':
                    result = self.check_domain(ioc_value)
                else:
                    print(f"Unsupported IOC type: {ioc_type}")
                    continue
                
                if result:
                    results[f"{ioc_type}_{ioc_value}"] = result
                    # Output brief result information
                    if result['malicious'] > 0:
                        print(f"  [WARNING] DETECTED: {result['detection_ratio']} engines consider it malicious")
                    elif result['suspicious'] > 0:
                        print(f"  [WARNING] SUSPICIOUS: {result['detection_ratio']} engines consider it suspicious")
                    else:
                        print(f"  [OK] CLEAN: {result['detection_ratio']} engines detected no threats")
                else:
                    print(f"  [ERROR] Error checking {ioc_type}: {ioc_value}")
                    
            except Exception as e:
                print(f"  [ERROR] Error checking {ioc_type} {ioc_value}: {e}")
        
        return results
    
    def save_results(self, results: Dict, filename: str = "virustotal_results.json"):
        """
        Save check results to JSON file
        
        Args:
            results: Check results
            filename: Filename to save
        """
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            print(f"VirusTotal results saved to {filename}")
        except Exception as e:
            print(f"Error saving results: {e}")


def load_vt_config(config_file: str = "vt_config.json") -> Optional[str]:
    """
    Load VirusTotal configuration from file
    
    Args:
        config_file: Path to configuration file
        
    Returns:
        API key or None
    """
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                return config.get('api_key')
    except Exception as e:
        print(f"Error loading VirusTotal configuration: {e}")
    
    return None
