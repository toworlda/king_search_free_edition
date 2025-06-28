#!/usr/bin/env python3
"""
API IDOR Privilege Escalation Tester

This script tests for Insecure Direct Object Reference (IDOR) vulnerabilities
by systematically changing user IDs in API requests and analyzing responses
for privilege escalation indicators.

Usage:
    python3 idor_tester.py --config config.json --output results.json

Features:
- Multi-threaded testing for efficient scanning
- Detailed response analysis for potential privilege escalation
- Customizable request parameters and headers
- Success indicators based on response content and status codes
- Output in various formats (JSON, CSV, HTML report)
"""

import argparse
import json
import csv
import requests
import threading
import time
import logging
import concurrent.futures
import re
import sys
import copy
import base64
from urllib.parse import urlparse, parse_qs, urlencode
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Set, Tuple, Union
from datetime import datetime
from pathlib import Path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

@dataclass
class IDORTest:
    endpoint: str
    method: str
    original_id: str
    target_id: str
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    data: Dict[str, Any] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)
    success_status_codes: List[int] = field(default_factory=list)
    id_locations: List[str] = field(default_factory=list)  # url, params, json, headers, cookies

@dataclass
class TestResult:
    test: IDORTest
    vulnerable: bool
    status_code: int
    response_time: float
    response_length: int
    evidence: str = ""
    error: str = ""

class IDORTester:
    def __init__(self, config_path: str, output_path: str, threads: int = 10, 
                 verbose: bool = False, timeout: int = 10):
        self.config_path = config_path
        self.output_path = output_path
        self.threads = threads
        self.verbose = verbose
        self.timeout = timeout
        self.results: List[TestResult] = []
        self.session = requests.Session()
        self.config = self._load_config()
        self.start_time = time.time()
        self.tests_performed = 0
        self.vulnerabilities_found = 0

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                logger.info(f"Loaded configuration from {self.config_path}")
                return config
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.error(f"Error loading configuration: {e}")
            sys.exit(1)

    def _prepare_tests(self) -> List[IDORTest]:
        """Prepare test cases from configuration"""
        tests = []
        credentials = self.config.get('credentials', [])
        
        # Get test parameters
        test_params = self.config.get('test_parameters', {})
        self.timeout = test_params.get('timeout', self.timeout)
        self.threads = test_params.get('threads', self.threads)
        
        # For each endpoint in target_endpoints
        for endpoint_config in self.config.get('target_endpoints', []):
            endpoint_url = endpoint_config.get('url')
            method = endpoint_config.get('method', 'GET')
            original_ids = endpoint_config.get('original_ids', [])
            target_ids = endpoint_config.get('target_ids', [])
            id_locations = endpoint_config.get('id_locations', ['url'])
            
            # Template data structures to be filled with IDs
            data_template = endpoint_config.get('data_template', {})
            params_template = endpoint_config.get('params_template', {})
            cookies_template = endpoint_config.get('cookies_template', {})
            
            # For each credential
            for cred in credentials:
                # Prepare headers based on auth type
                headers = {}
                auth_type = cred.get('type')
                
                if auth_type == 'basic_auth':
                    headers['Authorization'] = f"Basic {cred.get('value')}"
                elif auth_type == 'bearer_token':
                    headers['Authorization'] = f"Bearer {cred.get('value')}"
                
                # Optional custom headers
                custom_headers = endpoint_config.get('headers', {})
                headers.update(custom_headers)
                
                # For each original ID
                for original_id in original_ids:
                    # For each target ID
                    for target_id in target_ids:
                        # Replace placeholder in URL if needed
                        actual_endpoint = endpoint_url
                        if '{user_id}' in actual_endpoint:
                            actual_endpoint = actual_endpoint.replace('{user_id}', original_id)
                        
                        # Create deep copies of templates to avoid modifying originals
                        data = copy.deepcopy(data_template)
                        params = copy.deepcopy(params_template)
                        cookies = copy.deepcopy(cookies_template)
                        
                        # Replace {user_id} placeholders in templates
                        data = self._replace_id_in_value(data, '{user_id}', original_id)
                        params = self._replace_id_in_value(params, '{user_id}', original_id)
                        cookies = self._replace_id_in_value(cookies, '{user_id}', original_id)
                        
                        # Create test case
                        test = IDORTest(
                            endpoint=actual_endpoint,
                            method=method,
                            original_id=original_id,
                            target_id=target_id,
                            headers=headers,
                            params=params,
                            data=data,
                            cookies=cookies,
                            success_indicators=endpoint_config.get('success_indicators', []),
                            failure_indicators=endpoint_config.get('failure_indicators', []),
                            success_status_codes=endpoint_config.get('success_status_codes', [200]),
                            id_locations=id_locations
                        )
                        tests.append(test)
        
        return tests

    def _replace_id_in_value(self, value: Any, original_id: str, target_id: str) -> Any:
        """Replace original ID with target ID in a value"""
        if isinstance(value, str):
            return value.replace(original_id, target_id)
        elif isinstance(value, dict):
            return {k: self._replace_id_in_value(v, original_id, target_id) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._replace_id_in_value(item, original_id, target_id) for item in value]
        else:
            return value

    def _replace_ids(self, test: IDORTest) -> IDORTest:
        """Replace all occurrences of original ID with target ID based on id_locations"""
        modified_test = IDORTest(**asdict(test))
        
        for location in test.id_locations:
            if location == 'url':
                modified_test.endpoint = modified_test.endpoint.replace(test.original_id, test.target_id)
            elif location == 'params':
                modified_test.params = self._replace_id_in_value(modified_test.params, test.original_id, test.target_id)
            elif location == 'json':
                modified_test.data = self._replace_id_in_value(modified_test.data, test.original_id, test.target_id)
            elif location == 'headers':
                modified_test.headers = self._replace_id_in_value(modified_test.headers, test.original_id, test.target_id)
            elif location == 'cookies':
                modified_test.cookies = self._replace_id_in_value(modified_test.cookies, test.original_id, test.target_id)
        
        return modified_test

    def _execute_test(self, test: IDORTest) -> TestResult:
        """Execute a single test case"""
        self.tests_performed += 1
        modified_test = self._replace_ids(test)
        
        try:
            start_time = time.time()
            
            if self.verbose:
                logger.info(f"Testing {modified_test.method} {modified_test.endpoint} - Original ID: {test.original_id}, Target ID: {test.target_id}")
            
            response = self.session.request(
                method=modified_test.method,
                url=modified_test.endpoint,
                headers=modified_test.headers,
                params=modified_test.params,
                json=modified_test.data if modified_test.method in ['POST', 'PUT', 'PATCH'] else None,
                cookies=modified_test.cookies,
                timeout=self.timeout,
                verify=False
            )
            
            response_time = time.time() - start_time
            
            # Check for vulnerability indicators
            vulnerable = False
            evidence = ""
            
            # Check status code
            if response.status_code in modified_test.success_status_codes:
                # Check for success indicators in response
                response_text = response.text
                for indicator in modified_test.success_indicators:
                    if indicator in response_text:
                        vulnerable = True
                        evidence = f"Found success indicator: {indicator}"
                        break
                
                # Check for failure indicators
                for indicator in modified_test.failure_indicators:
                    if indicator in response_text:
                        vulnerable = False
                        break
            
            if vulnerable:
                self.vulnerabilities_found += 1
                logger.warning(f"{Fore.RED}[VULNERABLE] {modified_test.method} {modified_test.endpoint} - Status: {response.status_code}{Style.RESET_ALL}")
            elif self.verbose:
                logger.info(f"{Fore.GREEN}[SECURE] {modified_test.method} {modified_test.endpoint} - Status: {response.status_code}{Style.RESET_ALL}")
            
            return TestResult(
                test=modified_test,
                vulnerable=vulnerable,
                status_code=response.status_code,
                response_time=response_time,
                response_length=len(response.content),
                evidence=evidence
            )
            
        except Exception as e:
            logger.error(f"Error testing {modified_test.endpoint}: {e}")
            return TestResult(
                test=modified_test,
                vulnerable=False,
                status_code=0,
                response_time=0,
                response_length=0,
                error=str(e)
            )

    def run(self):
        """Run all tests"""
        tests = self._prepare_tests()
        total_tests = len(tests)
        
        logger.info(f"Starting IDOR testing with {total_tests} test cases across {self.threads} threads")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_test = {executor.submit(self._execute_test, test): test for test in tests}
            
            for future in concurrent.futures.as_completed(future_to_test):
                test = future_to_test[future]
                try:
                    result = future.result()
                    self.results.append(result)
                except Exception as e:
                    logger.error(f"Error processing test result: {e}")
        
        self._save_results()
        self._print_summary()

    def _save_results(self):
        """Save test results to output file"""
        output_format = self.output_path.split('.')[-1].lower()
        
        if output_format == 'json':
            with open(self.output_path, 'w') as f:
                json.dump([{
                    'endpoint': r.test.endpoint,
                    'method': r.test.method,
                    'original_id': r.test.original_id,
                    'target_id': r.test.target_id,
                    'vulnerable': r.vulnerable,
                    'status_code': r.status_code,
                    'response_time': r.response_time,
                    'response_length': r.response_length,
                    'evidence': r.evidence,
                    'error': r.error
                } for r in self.results], f, indent=2)
        
        elif output_format == 'csv':
            with open(self.output_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Endpoint', 'Method', 'Original ID', 'Target ID', 'Vulnerable', 
                                'Status Code', 'Response Time', 'Response Length', 'Evidence', 'Error'])
                
                for r in self.results:
                    writer.writerow([
                        r.test.endpoint, r.test.method, r.test.original_id, r.test.target_id,
                        r.vulnerable, r.status_code, r.response_time, r.response_length,
                        r.evidence, r.error
                    ])
        
        elif output_format == 'html':
            self._generate_html_report()
        
        logger.info(f"Results saved to {self.output_path}")

    def _generate_html_report(self):
        """Generate HTML report from test results"""
        vulnerable_count = sum(1 for r in self.results if r.vulnerable)
        total_count = len(self.results)
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>IDOR Vulnerability Test Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .summary {{ background-color: #f5f5f5; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
                .vulnerable {{ background-color: #ffebee; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
                .vulnerable-row {{ background-color: #ffebee; }}
                .success {{ color: green; }}
                .fail {{ color: red; }}
            </style>
        </head>
        <body>
            <h1>IDOR Vulnerability Test Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Total tests: {total_count}</p>
                <p>Vulnerabilities found: <span class="fail">{vulnerable_count}</span></p>
                <p>Success rate: <span class="{
                    'success' if vulnerable_count == 0 else 'fail'
                }">{(1 - vulnerable_count / total_count) * 100:.2f}%</span></p>
                <p>Execution time: {(time.time() - self.start_time):.2f} seconds</p>
            </div>
            
            <h2>Test Results</h2>
            <table>
                <tr>
                    <th>Endpoint</th>
                    <th>Method</th>
                    <th>Original ID</th>
                    <th>Target ID</th>
                    <th>Status</th>
                    <th>Status Code</th>
                    <th>Response Time</th>
                    <th>Response Length</th>
                    <th>Evidence</th>
                </tr>
        """
        
        for r in self.results:
            html += f"""
                <tr class="{'vulnerable-row' if r.vulnerable else ''}">
                    <td>{r.test.endpoint}</td>
                    <td>{r.test.method}</td>
                    <td>{r.test.original_id}</td>
                    <td>{r.test.target_id}</td>
                    <td class="{'fail' if r.vulnerable else 'success'}">{
                        'VULNERABLE' if r.vulnerable else 'SECURE'
                    }</td>
                    <td>{r.status_code}</td>
                    <td>{r.response_time:.2f}s</td>
                    <td>{r.response_length}</td>
                    <td>{r.evidence}</td>
                </tr>
            """
        
        html += """
            </table>
        </body>
        </html>
        """
        
        with open(self.output_path, 'w') as f:
            f.write(html)

    def _print_summary(self):
        """Print summary of test results"""
        total_time = time.time() - self.start_time
        
        print(f"\n{Fore.CYAN}===== IDOR Testing Summary ====={Style.RESET_ALL}")
        print(f"Total tests performed: {self.tests_performed}")
        print(f"Vulnerabilities found: {Fore.RED if self.vulnerabilities_found > 0 else Fore.GREEN}{self.vulnerabilities_found}{Style.RESET_ALL}")
        print(f"Success rate: {Fore.GREEN if self.vulnerabilities_found == 0 else Fore.RED}{(1 - self.vulnerabilities_found / max(1, self.tests_performed)) * 100:.2f}%{Style.RESET_ALL}")
        print(f"Total execution time: {total_time:.2f} seconds")
        print(f"Average time per test: {(total_time / max(1, self.tests_performed)):.2f} seconds")
        print(f"Results saved to: {self.output_path}")
        print(f"{Fore.CYAN}============================={Style.RESET_ALL}\n")

def encode_credentials(username, password):
    """Encode credentials to Base64 for Basic Auth"""
    auth_string = f"{username}:{password}"
    encoded = base64.b64encode(auth_string.encode()).decode()
    return encoded

def decode_credentials(encoded):
    """Decode Base64 encoded credentials"""
    decoded = base64.b64decode(encoded).decode()
    if ':' in decoded:
        username, password = decoded.split(':', 1)
        return username, password
    return decoded, None

def main():
    parser = argparse.ArgumentParser(description='IDOR Vulnerability Tester')
    parser.add_argument('--config', required=True, help='Path to configuration file')
    parser.add_argument('--output', required=True, help='Path to output file (json, csv, or html)')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads to use')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--generate-creds', action='store_true', help='Generate and encode credentials only')
    parser.add_argument('--username', help='Username for credentials generation')
    parser.add_argument('--password', help='Password for credentials generation')
    
    args = parser.parse_args()
    
    # If just generating credentials
    if args.generate_creds:
        if not args.username or not args.password:
            print("Error: Username and password are required for credentials generation")
            return
            
        encoded = encode_credentials(args.username, args.password)
        print(f"\nCredentials for {args.username}:{args.password}")
        print(f"Base64 Encoded: {encoded}")
        return
    
    # Run the main tester
    tester = IDORTester(
        config_path=args.config,
        output_path=args.output,
        threads=args.threads,
        verbose=args.verbose,
        timeout=args.timeout
    )
    
    tester.run()

if __name__ == '__main__':
    main()
