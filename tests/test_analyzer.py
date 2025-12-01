import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from analyzer import load_iocs, search_iocs

class TestAnalyzer(unittest.TestCase):
    def test_load_iocs(self):
        iocs = load_iocs(os.path.join(os.path.dirname(__file__), '../src/ioc_list.json'))
        self.assertIn("ips", iocs)
        self.assertIsInstance(iocs["ips"], list)

    def test_search_iocs(self):
        iocs = {"ips": ["1.2.3.4"], "domains": [], "file_hashes": [], "urls": []}
        result = search_iocs("Connection from 1.2.3.4 detected", iocs)
        self.assertIn(('ip', '1.2.3.4'), result)
    
    def test_search_urls(self):
        iocs = {"ips": [], "domains": [], "file_hashes": [], "urls": ["http://example.com/malicious"]}
        result = search_iocs("Accessing http://example.com/malicious", iocs)
        self.assertIn(('url', 'http://example.com/malicious'), result)

if __name__ == '__main__':
    unittest.main()
