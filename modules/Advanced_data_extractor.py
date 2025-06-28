#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import json
import html
import csv
import yaml
import logging
import hashlib
import mmap
import platform
import subprocess
import importlib
import multiprocessing
import xml.etree.ElementTree as ET
import base64
import argparse
import shutil
import mimetypes
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from typing import Dict, List, Any, Optional
from typing import Dict, List, Any, Set, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from bs4 import BeautifulSoup
from collections import defaultdict
from tqdm import tqdm
from pathlib import Path
from jinja2 import Template
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import cpu_count
from html import escape

class DataExtractor:
    def __init__(self, config_path: str = 'config.yaml'):
        """
        Initialize the data extractor with configuration
        """
        # List of data types to detect
        self.data_types = [
            # Authentication & API Keys
            "jwt_token", "oauth_token", "api_key", "access_token","authorization_token", "authorization_bearer", "refresh_token",

            # Cloud Provider Credentials
            "aws_credentials", "azure_credentials", "gcp_credentials", "heroku_api_key", "digital_ocean_token",

            # Development Platform Tokens
            "github_token", "gitlab_token", "bitbucket_token", "docker_registry_token", "npm_token", "pypi_token",

            # Payment & Financial
            "stripe_api_key", "paypal_token", "square_access_token", "credit_card_data", "bank_account_details",
            
            # Communication Platforms
            "slack_token", "discord_token", "telegram_token", "sendgrid_api_key", "mailchimp_api_key",
            
            # Sensitive Personal Data
            "email_credentials", "phone_number", "social_security_number", "passport_number", "personal_id",

            # Cryptographic & Security
            "encryption_key", "private_key", "certificate", "ssl_private_key", "pgp_key", "ssh_key",

            # Hashes & Identifiers
            "md5_hash", "sha1_hash", "sha256_hash", "uuid", "database_connection_string"
        ]
        
        # Comprehensive regex patterns to detect sensitive data
        self.sensitive_patterns = {
            # Authentication Patterns
            'authorization_basic': r'(?i)basic\s+[a-zA-Z0-9=:_\+\/-]{5,100}',
            'authorization_bearer': r'(?i)bearer\s+[a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
            'authorization_api_1': r'(?i)api[_\s]*key\s*[=:]\s*[a-zA-Z0-9_\-]{5,100}',

            # API Keys and Tokens
            'api_token': r'(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}',
            'api_key': r'(?i)(?:api[_\-\s]?key)[\s=:]+[\'"]?([A-Za-z0-9-_]{10,100})[\'"]?',
            'jwt_token': r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.?[A-Za-z0-9_-]+)',
            'heroku_api_key': r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})',
            'oauth_token': r'(?i)(?:access|refresh)[_\s]*token[\s=:]+([A-Za-z0-9_\-]{10,400})',
            'json_web_token': r'(ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)',
            'square_access_token': r'(sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60})',
            'google_api': r'(AIza[0-9A-Za-z-_]{35})',
            'google_gmail_api': r'AIza[0-9A-Za-z\\-_]{35}',
            'google_gmail_auth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',

            # Cloud and Platform Credentials
            'github_token': r'(ghp_[0-9a-zA-Z]{36})',
            'azure_client_id': r'(?i)(azure_client_id|azure_application_id|AZURE_TENANT_ID)[\s:=]+([0-9a-f-]{36})',
            'google_oauth': r'(ya29\.[0-9A-Za-z\-_]+)',
            'google_drive_oauth': r'([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)',
            'square_oauth': r'(sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43})',
            'facebook_access_token': r'(EAACEdEose0cBA[0-9A-Za-z]+)',
            'facebook_oauth': r'[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*[\'"][0-9a-f]{32}[\'"]',

            # Financial and Personal Data
            'credit_card': r'^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6011[0-9]{12}|622((12[6-9]|1[3-9][0-9])|([2-8][0-9][0-9])|(9(([0-1][0-9])|(2[0-5]))))[0-9]{10}|64[4-9][0-9]{13}|65[0-9]{14}|3(?:0[0-5]|[68][0-9])[0-9]{11}|3[47][0-9]{13})*$',
            'credit_card': r'^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6011[0-9]{12}|622(?:12[6-9]|1[3-9][0-9]|[2-8][0-9]{2}|9(?:[0-1][0-9]|2[0-5]))[0-9]{10}|64[4-9][0-9]{13}|65[0-9]{14}|3(?:0[0-5]|[68][0-9])[0-9]{11}|3[47][0-9]{13})$',
            'paypal_braintree_token': r'(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})',
            'social_security_number': r'([0-9]{3}-[0-9]{2}-[0-9]{4})',  # Fixed escaped braces
            'phone_number': r'(^\+[0-9]{2}|^\+[0-9]{2}\(0\)|^\(\+[0-9]{2}\)\(0\)|^00[0-9]{2}|^0)([0-9]{9}$|[0-9\-\s]{10}$)',
            'btc_address': r'\b([13][a-km-zA-HJ-NP-Z0-9]{25,34})\b',
            'eth_address': r'\b(0x[a-fA-F0-9]{40})\b',
            'ltc_address': r'\b([L3][a-km-zA-HJ-NP-Z1-9]{26,33})\b',
            'percentage_2_decimal': r'^(-?[0-9]{0,2}(\.[0-9]{1,2})?$|^-?(100)(\.[0]{1,2})?)$',

            # Cryptographic Artifacts
            'private_key': r'-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----[\s\S]+?-----END (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----',
            'pgp_private_block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----',
            'ssl_cert': r'(CERTIFICATE|SSL).*',

            # Hashes
            'md5_hash': r'\b([a-fA-F0-9]{32})\b',
            'sha1_hash': r'\b([a-fA-F0-9]{40})\b',
            'sha256_hash': r'\b([a-fA-F0-9]{64})\b',
            'sha512_hash': r'\b([a-fA-F0-9]{128})\b',
        }
        
        # Configuration and logging setup
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        # Create necessary directories
        try:
            os.makedirs('Reports', exist_ok=True)
            os.makedirs('Reports/Data', exist_ok=True)
            os.makedirs('Reports/Logs', exist_ok=True)
        except PermissionError:
            logging.error("Insufficient permissions to create directories")
            raise

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """
        Load configuration from YAML file
        """
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as file:
                    return yaml.safe_load(file)
            else:
                logging.warning(f"Config file {config_path} not found. Using default settings.")
                return self._create_default_config(config_path)
        except Exception as e:
            logging.error(f"Error loading configuration: {e}")
            return {}

    def _create_default_config(self, config_path: str) -> Dict[str, Any]:
        """
        Create a default configuration file if none exists
        """
        default_config = {
            'max_file_size': 10 * 1024 * 1024 * 1024,  # 10 GB
            'supported_extensions': [
                '.txt', '.log', '.json', '.xml', '.yaml', '.yml', 
                '.config', '.ini', '.env', '.js', '.py', '.html', 
                '.csv', '.md', '.sh', '.conf', '.properties'
            ],
            'parallel_processing': True,
            'output_formats': ['html', 'csv', 'json'],
            'report_directory': 'Reports/Data',
            'log_directory': 'Reports/Logs',
            'deduplicate_results': True
        }
        
        try:
            with open(config_path, 'w') as file:
                yaml.dump(default_config, file)
            logging.info(f"Created default configuration at {config_path}")
            return default_config
        except Exception as e:
            logging.error(f"Failed to create default config: {e}")
            return default_config

    def _setup_logging(self):
        """
        Configure logging
        """
        log_directory = self.config.get('log_directory', 'Reports/Logs')
        os.makedirs(log_directory, exist_ok=True)
        
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                logging.FileHandler(f"{log_directory}/data_extractor.log"),
                logging.StreamHandler()
            ]
        )

    def _risk_classification(self, data_type: str) -> str:
        """
        Classify the risk level of detected data types
        """
        risk_map = {
            # Critical Risk
            "aws_credentials": "Critical",
            "azure_credentials": "Critical",
            "credit_card_data": "Critical",
            "jwt_token": "Critical",
            "email_credentials": "Critical",
            "private_key": "Critical",
            
            # High Risk
            "api_key": "High",
            "github_token": "High",
            "access_token": "High",
            "database_connection_string": "High",
            "authorization_basic": "High",
            "authorization_bearer": "High",
            "authorization_api": "High",
            
            # Medium Risk
            "phone_number": "Medium",
            "email_password": "Medium",
            "credit_card_1": "Medium",
            "credit_card_2": "Medium",
            "dollar_amount": "Medium",
            "paypal_braintree_token": "Medium",
            
            # Low Risk
            "domain": "Low",
            "ip_address": "Low"
        }
        return risk_map.get(data_type, "Medium")

    def _memory_mapped_read(self, file_path: str) -> str:
        """
        Memory-efficient file reading using memory mapping
        """
        try:
            with open(file_path, 'rb') as f:
                # Use memory mapping for efficient file reading
                mmapped_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                content = mmapped_file.read().decode('utf-8', errors='ignore')
                mmapped_file.close()
                return content
        except Exception as e:
            logging.error(f"Memory mapping error for {file_path}: {e}")
            # Fall back to normal file reading for smaller files
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    return f.read()
            except Exception as e2:
                logging.error(f"Failed to read file {file_path}: {e2}")
                return ""

    def extract_sensitive_data(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Extract sensitive data from a single file
        """
        # Check if we should process this file
        if not self._should_process_file(file_path):
            logging.info(f"Skipping file: {file_path}")
            return []

        try:
            logging.info(f"Processing file: {file_path}")
            content = self._memory_mapped_read(file_path)
            if not content:
                return []
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")
            return []

        extracted_data = []

        # Process each pattern
        for pattern_name, pattern in self.sensitive_patterns.items():
            if isinstance(pattern, dict):  # Handle nested patterns like crypto addresses
                for sub_name, sub_pattern in pattern.items():
                    try:
                        matches = re.findall(sub_pattern, content, re.IGNORECASE | re.MULTILINE)
                        if matches:
                            for match in set(matches):  # Deduplicate matches within file
                                extracted_data.append({
                                    'file': os.path.basename(file_path),
                                    'file_path': file_path,
                                    'data_type': f'{pattern_name}_{sub_name}',
                                    'value': match,
                                    'risk_level': self._risk_classification(f'{pattern_name}_{sub_name}')
                                })
                    except re.error as e:
                        logging.error(f"Regex error in pattern {sub_name}: {e}")
            else:
                try:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    if matches:
                        for match in set(matches):  # Deduplicate matches within file
                            if isinstance(match, tuple):
                                match = ' '.join(str(m) for m in match if m)
                            extracted_data.append({
                                'file': os.path.basename(file_path),
                                'file_path': file_path,
                                'data_type': pattern_name,
                                'value': match,
                                'risk_level': self._risk_classification(pattern_name)
                            })
                except re.error as e:
                    logging.error(f"Regex error in pattern {pattern_name}: {e}")

        return extracted_data

    def _should_process_file(self, file_path: str) -> bool:
        """
        Determine if a file should be processed based on size and extension
        """
        max_file_size = self.config.get('max_file_size', 100 * 1024 * 1024)  # Default 100 MB
        supported_extensions = set(self.config.get('supported_extensions', [
            '.txt', '.log', '.json', '.xml', '.yaml', '.yml', 
            '.config', '.ini', '.env', '.js', '.py', '.html', 
            '.csv', '.md', '.sh', '.conf', '.properties'
        ]))

        try:
            # Check if file exists and is a regular file
            if not os.path.isfile(file_path):
                return False
                
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > max_file_size:
                logging.info(f"File too large: {file_path} ({file_size} bytes)")
                return False
                
            # Check file extension
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext not in supported_extensions:
                return False
                
            return True
        except Exception as e:
            logging.error(f"Error checking file {file_path}: {e}")
            return False

    def _deduplicate_data(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate extracted data across all files
        """
        if not self.config.get('deduplicate_results', True):
            return data
            
        unique_data = []
        seen = set()
        
        for item in data:
            # Create a unique key based on data type and value
            key = (item['data_type'], str(item['value']))
            
            if key not in seen:
                unique_data.append(item)
                seen.add(key)
                
        logging.info(f"Deduplicated {len(data) - len(unique_data)} entries")
        return unique_data

    def process_directory(self, directory: str) -> List[Dict[str, Any]]:
        """
        Process all files in a directory (including subdirectories)
        """
        all_extracted_data = []
        
        # Collect all valid files to process
        file_list = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                # Pre-filter files to avoid loading them into memory unnecessarily
                if self._should_process_file(file_path):
                    file_list.append(file_path)
        
        logging.info(f"Found {len(file_list)} files to process in {directory}")
        
        if self.config.get('parallel_processing', True):
            # Use ProcessPoolExecutor for parallel processing
            cpu_count = multiprocessing.cpu_count()
            max_workers = min(cpu_count, len(file_list))
            
            if max_workers > 0:
                logging.info(f"Processing with {max_workers} workers")
                with ProcessPoolExecutor(max_workers=max_workers) as executor:
                    futures = {
                        executor.submit(self.extract_sensitive_data, file_path): file_path 
                        for file_path in file_list
                    }
                    
                    total = len(futures)
                    completed = 0
                    
                    for future in as_completed(futures):
                        try:
                            file_path = futures[future]
                            data = future.result()
                            all_extracted_data.extend(data)
                            
                            # Progress update
                            completed += 1
                            if completed % 10 == 0 or completed == total:
                                logging.info(f"Progress: {completed}/{total} files processed")
                                
                        except Exception as e:
                            logging.error(f"Processing error: {e}")
        else:
            # Sequential processing
            for idx, file_path in enumerate(file_list, 1):
                try:
                    data = self.extract_sensitive_data(file_path)
                    all_extracted_data.extend(data)
                    
                    # Progress update
                    if idx % 10 == 0 or idx == len(file_list):
                        logging.info(f"Progress: {idx}/{len(file_list)} files processed")
                        
                except Exception as e:
                    logging.error(f"Error processing {file_path}: {e}")
        
        # Deduplicate the data
        deduplicated_data = self._deduplicate_data(all_extracted_data)
        logging.info(f"Found {len(deduplicated_data)} unique sensitive data items")
        
        return deduplicated_data

    def process_single_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Process a single file and return extracted data
        """
        if not os.path.exists(file_path):
            logging.error(f"File does not exist: {file_path}")
            return []
            
        if not os.path.isfile(file_path):
            logging.error(f"Not a file: {file_path}")
            return []
            
        extracted_data = self.extract_sensitive_data(file_path)
        return extracted_data

    def generate_html_report(self, extracted_data: List[Dict[str, Any]]) -> str:
        """
        Generate an HTML report of extracted sensitive data
        """
        if not extracted_data:
            logging.warning("No data to generate report")
            return ""
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = self.config.get('report_directory', 'Reports/Data')
        os.makedirs(report_dir, exist_ok=True)
        report_path = f'{report_dir}/sensitive_data_report_{timestamp}.html'

        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Sensitive Data Extraction Report</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    margin: 20px;
                    background-color: #f8f9fa;
                }
                h1 {
                    color: #333;
                    border-bottom: 2px solid #ddd;
                    padding-bottom: 10px;
                }
                .summary {
                    background-color: #fff;
                    border: 1px solid #ddd;
                    padding: 15px;
                    margin-bottom: 20px;
                    border-radius: 5px;
                }
                table { 
                    width: 100%; 
                    border-collapse: collapse; 
                    margin-top: 20px;
                    background-color: #fff;
                }
                th, td { 
                    border: 1px solid #ddd; 
                    padding: 10px; 
                    text-align: left; 
                }
                th {
                    background-color: #f2f2f2;
                    position: sticky;
                    top: 0;
                }
                tr:nth-child(even) {
                    background-color: #f9f9f9;
                }
                .Critical { background-color: #ffcccc; }
                .High { background-color: #fff2cc; }
                .Medium { background-color: #e6ffcc; }
                .Low { background-color: #e6f2ff; }
                .filter-section {
                    background-color: #fff;
                    padding: 15px;
                    margin-bottom: 20px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                }
                .btn {
                    padding: 5px 10px;
                    margin: 0 5px;
                    border: none;
                    border-radius: 3px;
                    cursor: pointer;
                }
                .btn-risk {
                    background-color: #f8f9fa;
                    border: 1px solid #ddd;
                }
                .search-box {
                    padding: 5px;
                    width: 300px;
                    margin-right: 10px;
                }
            </style>
            <script>
                function filterTable() {
                    var input = document.getElementById('searchBox').value.toLowerCase();
                    var riskFilters = [];
                    
                    // Get selected risk levels
                    var checkboxes = document.querySelectorAll('input[name="risk"]:checked');
                    for (var i = 0; i < checkboxes.length; i++) {
                        riskFilters.push(checkboxes[i].value);
                    }
                    
                    var table = document.getElementById('dataTable');
                    var tr = table.getElementsByTagName('tr');
                    
                    for (var i = 1; i < tr.length; i++) {
                        var tdFile = tr[i].getElementsByTagName('td')[0];
                        var tdType = tr[i].getElementsByTagName('td')[1];
                        var tdValue = tr[i].getElementsByTagName('td')[2];
                        var tdRisk = tr[i].getElementsByTagName('td')[3];
                        
                        if (tdFile && tdType && tdValue && tdRisk) {
                            var fileText = tdFile.textContent || tdFile.innerText;
                            var typeText = tdType.textContent || tdType.innerText;
                            var valueText = tdValue.textContent || tdValue.innerText;
                            var riskText = tdRisk.textContent || tdRisk.innerText;
                            
                            var textMatch = fileText.toLowerCase().indexOf(input) > -1 || 
                                          typeText.toLowerCase().indexOf(input) > -1 || 
                                          valueText.toLowerCase().indexOf(input) > -1;
                                          
                            var riskMatch = riskFilters.length === 0 || riskFilters.includes(riskText);
                            
                            if (textMatch && riskMatch) {
                                tr[i].style.display = "";
                            } else {
                                tr[i].style.display = "none";
                            }
                        }
                    }
                }
                
                function toggleAllRisks(checked) {
                    var checkboxes = document.querySelectorAll('input[name="risk"]');
                    for (var i = 0; i < checkboxes.length; i++) {
                        checkboxes[i].checked = checked;
                    }
                    filterTable();
                }
            </script>
        </head>
        <body>
            <h1>Sensitive Data Extraction Report</h1>
            
            <div class="summary">
                <h2>Summary</h2>
                <p>Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
                <p>Total items found: """ + str(len(extracted_data)) + """</p>
            </div>
            
            <div class="filter-section">
                <h2>Filter Results</h2>
                <div>
                    <input type="text" id="searchBox" class="search-box" placeholder="Search for files, data types, or values..." onkeyup="filterTable()">
                </div>
                <div style="margin-top: 10px;">
                    <b>Risk Level: </b>
                    <button class="btn btn-risk" onclick="toggleAllRisks(true)">Select All</button>
                    <button class="btn btn-risk" onclick="toggleAllRisks(false)">Clear All</button>
                    <label><input type="checkbox" name="risk" value="Critical" checked onchange="filterTable()"> Critical</label>
                    <label><input type="checkbox" name="risk" value="High" checked onchange="filterTable()"> High</label>
                    <label><input type="checkbox" name="risk" value="Medium" checked onchange="filterTable()"> Medium</label>
                    <label><input type="checkbox" name="risk" value="Low" checked onchange="filterTable()"> Low</label>
                </div>
            </div>
            
            <table id="dataTable">
                <tr>
                    <th>File</th>
                    <th>Data Type</th>
                    <th>Value</th>
                    <th>Risk Level</th>
                </tr>
        """

        for item in extracted_data:
            risk_class = item.get('risk_level', 'Medium')
            html_content += f"""
                <tr class="{risk_class}">
                    <td>{html.escape(item['file'])}</td>
                    <td>{html.escape(item['data_type'])}</td>
                    <td>{html.escape(str(item['value']))}</td>
                    <td>{html.escape(risk_class)}</td>
                </tr>
            """

        html_content += """
            </table>
        </body>
        </html>
        """

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logging.info(f"HTML report generated: {report_path}")
        return report_path

    def generate_csv_report(self, extracted_data: List[Dict[str, Any]]) -> str:
        """
        Generate a CSV report of extracted sensitive data
        """
        if not extracted_data:
            logging.warning("No data to generate CSV report")
            return ""
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = self.config.get('report_directory', 'Reports/Data')
        os.makedirs(report_dir, exist_ok=True)
        report_path = f'{report_dir}/sensitive_data_report_{timestamp}.csv'
        
        fieldnames = ['file', 'file_path', 'data_type', 'value', 'risk_level']
        
        with open(report_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for item in extracted_data:
                writer.writerow({
                    'file': item['file'],
                    'file_path': item.get('file_path', ''),
                    'data_type': item['data_type'],
                    'value': str(item['value']),
                    'risk_level': item.get('risk_level', 'Medium')
                })
                
        logging.info(f"CSV report generated: {report_path}")
        return report_path
        
    def generate_json_report(self, extracted_data: List[Dict[str, Any]]) -> str:
        """
        Generate a JSON report of extracted sensitive data
        """
        if not extracted_data:
            logging.warning("No data to generate JSON report")
            return ""
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = self.config.get('report_directory', 'Reports/Data')
        os.makedirs(report_dir, exist_ok=True)
        report_path = f'{report_dir}/sensitive_data_report_{timestamp}.json'
        
        # Convert any non-serializable objects to strings
        serializable_data = []
        for item in extracted_data:
            serializable_item = {
                'file': item['file'],
                'file_path': item.get('file_path', ''),
                'data_type': item['data_type'],
                'value': str(item['value']),
                'risk_level': item.get('risk_level', 'Medium')
            }
            serializable_data.append(serializable_item)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(serializable_data, f, indent=4)
            
        logging.info(f"JSON report generated: {report_path}")
        return report_path

    def generate_reports(self, extracted_data: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Generate reports in all configured formats
        """
        reports = {}
        output_formats = self.config.get('output_formats', ['html', 'csv', 'json'])
        
        if 'html' in output_formats:
            html_path = self.generate_html_report(extracted_data)
            if html_path:
                reports['html'] = html_path
                
        if 'csv' in output_formats:
            csv_path = self.generate_csv_report(extracted_data)
            if csv_path:
                reports['csv'] = csv_path
                
        if 'json' in output_formats:
            json_path = self.generate_json_report(extracted_data)
            if json_path:
                reports['json'] = json_path
                
        return reports


def main():
    """
    Main function to run the data extractor
    """
    parser = argparse.ArgumentParser(description='Advanced Data Extractor Tool')
    parser.add_argument('--config', type=str, default='config.yaml', help='Path to config file')
    parser.add_argument('--file', type=str, help='Single file to scan')
    parser.add_argument('--dir', type=str, help='Directory to scan recursively')
    parser.add_argument('--output', type=str, choices=['html', 'csv', 'json', 'all'], default='all', 
                        help='Output format (default: all)')
    
    args = parser.parse_args()
    
    # Initialize data extractor
    try:
        extractor = DataExtractor(config_path=args.config)
    except Exception as e:
        print(f"Error initializing extractor: {e}")
        return 1
        
    extracted_data = []
    
    # Configure output formats
    if args.output != 'all':
        extractor.config['output_formats'] = [args.output]
    
    # Process file or directory
    if args.file:
        print(f"Scanning file: {args.file}")
        extracted_data = extractor.process_single_file(args.file)
    elif args.dir:
        print(f"Scanning directory: {args.dir}")
        extracted_data = extractor.process_directory(args.dir)
    else:
        # Interactive mode
        print("\n🔍 Data Extractor - Sensitive Data Scanner")
        print("1. Scan a single file")
        print("2. Scan an entire directory")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ")
        
        if choice == '1':
            file_path = input("Enter file path to scan: ")
            if file_path:
                print(f"Scanning file: {file_path}")
                extracted_data = extractor.process_single_file(file_path)
        elif choice == '2':
            dir_path = input("Enter directory path to scan: ")
            if dir_path:
                print(f"Scanning directory: {dir_path}")
                extracted_data = extractor.process_directory(dir_path)
        else:
            print("Exiting...")
            return 0
    
    # Generate reports
    if extracted_data:
        print(f"Found {len(extracted_data)} sensitive data items")
        reports = extractor.generate_reports(extracted_data)
        
        if reports:
            print("\nGenerated reports:")
            for format_type, path in reports.items():
                print(f"- {format_type.upper()}: {path}")
        else:
            print("No reports were generated")
    else:
        print("No sensitive data found")
    
    return 0


if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
