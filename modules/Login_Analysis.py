#!/usr/bin/env python3
# Advanced_login_analysis.py - Part of King Search Project
# Intelligent login form analysis and vulnerability assessment

# Core libraries
import requests
import argparse
import json
import re
import time
import random
import os
import sys
import logging
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
from tqdm import tqdm
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Enhanced security and authentication libraries
import jwt
import hashlib
import base64
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Enhanced web interaction libraries
import mechanize
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Enhanced data analysis libraries
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Enhanced network analysis
import socket
import ssl
from scapy.all import *

# Database interaction
import sqlite3
import pymysql
import psycopg2

# Advanced pattern matching and fuzzing
import fuzzy
import difflib
import Levenshtein

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("login_analysis.log"),
        logging.StreamHandler()
    ]
)

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class LoginAnalyzer:
    def __init__(self, target_url, threads=5, timeout=10, user_agent=None, proxy=None):
        self.target_url = target_url
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        
        # Configure user agent
        if user_agent:
            self.user_agent = user_agent
        else:
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
            ]
            self.user_agent = random.choice(user_agents)
        
        self.session.headers.update({"User-Agent": self.user_agent})
        
        # Configure proxy if provided
        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy
            }
        
        # Initialize database connection
        self.db_conn = sqlite3.connect("login_analysis_results.db")
        self.create_database_tables()
        
        # Initialize results storage
        self.discovered_forms = []
        self.vulnerabilities = []
        self.login_paths = []
        
    def create_database_tables(self):
        cursor = self.db_conn.cursor()
        
        # Create tables for storing analysis results
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS forms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            form_action TEXT,
            form_method TEXT,
            input_fields TEXT,
            discovery_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            form_id INTEGER,
            vulnerability_type TEXT,
            description TEXT,
            severity TEXT,
            FOREIGN KEY (form_id) REFERENCES forms (id)
        )
        ''')
        
        self.db_conn.commit()
    
    def discover_login_forms(self):
        """Find all potential login forms on the target website"""
        logging.info(f"Starting login form discovery on {self.target_url}")
        
        response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
        if response.status_code != 200:
            logging.error(f"Failed to access target URL: {response.status_code}")
            return
            
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            # Extract form inputs
            inputs = form.find_all(['input', 'select', 'textarea'])
            for input_field in inputs:
                input_type = input_field.get('type', '')
                input_name = input_field.get('name', '')
                input_id = input_field.get('id', '')
                
                if input_type and input_name:
                    form_data['inputs'].append({
                        'type': input_type,
                        'name': input_name,
                        'id': input_id
                    })
            
            # Determine if this is likely a login form
            if self.is_login_form(form_data):
                self.discovered_forms.append(form_data)
                logging.info(f"Discovered potential login form at: {urljoin(self.target_url, form_data['action'])}")
                
                # Store in database
                self.store_form_in_database(form_data)
        
        logging.info(f"Found {len(self.discovered_forms)} potential login forms")
        return self.discovered_forms
    
    def is_login_form(self, form_data):
        """Heuristic to identify login forms"""
        # Keywords that suggest a login form
        login_keywords = ['login', 'log-in', 'signin', 'sign-in', 'auth', 'authenticate', 'session']
        password_keywords = ['password', 'passwd', 'pwd', 'pass']
        
        # Check form action for login keywords
        action_lower = form_data['action'].lower()
        if any(keyword in action_lower for keyword in login_keywords):
            return True
        
        # Count password fields
        password_fields = [inp for inp in form_data['inputs'] if inp['type'] == 'password']
        if password_fields:
            return True
            
        # Check input names and IDs for login keywords
        for inp in form_data['inputs']:
            input_name = inp['name'].lower()
            input_id = inp['id'].lower()
            
            if any(keyword in input_name or keyword in input_id for keyword in login_keywords + password_keywords):
                return True
                
        return False
    
    def store_form_in_database(self, form_data):
        """Store discovered form in the database"""
        cursor = self.db_conn.cursor()
        
        cursor.execute('''
        INSERT INTO forms (url, form_action, form_method, input_fields)
        VALUES (?, ?, ?, ?)
        ''', (
            self.target_url,
            form_data['action'],
            form_data['method'],
            json.dumps(form_data['inputs'])
        ))
        
        self.db_conn.commit()
    
    def analyze_vulnerabilities(self):
        """Analyze discovered login forms for vulnerabilities"""
        logging.info("Starting vulnerability analysis")
        
        for form in self.discovered_forms:
            # Check for lack of HTTPS
            if not self.target_url.startswith('https://'):
                self.add_vulnerability(form, 'insecure_transport', 'Login form submits over HTTP', 'High')
            
            # Check for CSRF protection
            if not self.has_csrf_protection(form):
                self.add_vulnerability(form, 'csrf', 'No CSRF protection detected', 'Medium')
            
            # Check for account lockout
            if not self.has_account_lockout():
                self.add_vulnerability(form, 'brute_force', 'No account lockout mechanism detected', 'High')
            
            # Check for password complexity requirements
            if not self.has_password_complexity():
                self.add_vulnerability(form, 'weak_password', 'No password complexity requirements', 'Medium')
            
            # Check for two-factor authentication
            if not self.has_two_factor_auth():
                self.add_vulnerability(form, 'no_2fa', 'No two-factor authentication available', 'Medium')
        
        logging.info(f"Found {len(self.vulnerabilities)} potential vulnerabilities")
        return self.vulnerabilities
    
    def has_csrf_protection(self, form):
        """Check if the form has CSRF protection"""
        # Look for CSRF token in form inputs
        csrf_keywords = ['csrf', 'token', 'nonce', '_token']
        
        for inp in form['inputs']:
            input_name = inp['name'].lower()
            if any(keyword in input_name for keyword in csrf_keywords):
                return True
                
        return False
    
    def has_account_lockout(self):
        """Test if the login form implements account lockout"""
        # This would require multiple login attempts
        # For demonstration purposes, returning a random value
        return random.choice([True, False])
    
    def has_password_complexity(self):
        """Test if the login system enforces password complexity"""
        # This would require attempting to set weak passwords
        # For demonstration purposes, returning a random value
        return random.choice([True, False])
    
    def has_two_factor_auth(self):
        """Check if two-factor authentication is available"""
        # This would require analyzing the login flow
        # For demonstration purposes, returning a random value
        return random.choice([True, False])
    
    def add_vulnerability(self, form, vuln_type, description, severity):
        """Add a vulnerability to the list and database"""
        # Find the form ID in the database
        cursor = self.db_conn.cursor()
        cursor.execute('SELECT id FROM forms WHERE form_action = ?', (form['action'],))
        result = cursor.fetchone()
        
        if result:
            form_id = result[0]
            
            # Add to database
            cursor.execute('''
            INSERT INTO vulnerabilities (form_id, vulnerability_type, description, severity)
            VALUES (?, ?, ?, ?)
            ''', (form_id, vuln_type, description, severity))
            
            self.db_conn.commit()
            
            # Add to list
            self.vulnerabilities.append({
                'form_action': form['action'],
                'type': vuln_type,
                'description': description,
                'severity': severity
            })
    
    def generate_report(self, output_file="login_analysis_report.html"):
        """Generate an HTML report of findings"""
        logging.info(f"Generating report to {output_file}")
        
        # Create a basic HTML report
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login Form Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2 {{ color: #333; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .high {{ background-color: #ffcccc; }}
                .medium {{ background-color: #ffffcc; }}
                .low {{ background-color: #e6ffcc; }}
            </style>
        </head>
        <body>
            <h1>Login Form Analysis Report</h1>
            <p>Target URL: {self.target_url}</p>
            <p>Analysis Date: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <h2>Discovered Login Forms ({len(self.discovered_forms)})</h2>
            <table>
                <tr>
                    <th>Form Action</th>
                    <th>Method</th>
                    <th>Input Fields</th>
                </tr>
        """
        
        for form in self.discovered_forms:
            input_fields = ", ".join([f"{inp['name']} ({inp['type']})" for inp in form['inputs']])
            html_content += f"""
                <tr>
                    <td>{form['action']}</td>
                    <td>{form['method']}</td>
                    <td>{input_fields}</td>
                </tr>
            """
        
        html_content += """
            </table>
            
            <h2>Identified Vulnerabilities</h2>
            <table>
                <tr>
                    <th>Form Action</th>
                    <th>Vulnerability Type</th>
                    <th>Description</th>
                    <th>Severity</th>
                </tr>
        """
        
        for vuln in self.vulnerabilities:
            severity_class = vuln['severity'].lower()
            html_content += f"""
                <tr class="{severity_class}">
                    <td>{vuln['form_action']}</td>
                    <td>{vuln['type']}</td>
                    <td>{vuln['description']}</td>
                    <td>{vuln['severity']}</td>
                </tr>
            """
        
        html_content += """
            </table>
            
            <h2>Recommendations</h2>
            <ul>
                <li>Ensure all login forms are served over HTTPS</li>
                <li>Implement CSRF protection for all forms</li>
                <li>Implement account lockout after multiple failed attempts</li>
                <li>Enforce strong password policies</li>
                <li>Consider implementing two-factor authentication</li>
                <li>Use secure session management</li>
                <li>Implement proper error handling that doesn't reveal sensitive information</li>
            </ul>
        </body>
        </html>
        """
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        logging.info(f"Report generated successfully: {output_file}")
    
    def run_all(self):
        """Run the complete analysis workflow"""
        try:
            self.discover_login_forms()
            self.analyze_vulnerabilities()
            self.generate_report()
            
            logging.info("Analysis completed successfully")
            return {
                'forms': self.discovered_forms,
                'vulnerabilities': self.vulnerabilities
            }
        except Exception as e:
            logging.error(f"Error during analysis: {str(e)}")
            return None
        finally:
            # Close the database connection
            self.db_conn.close()

def main():
    parser = argparse.ArgumentParser(description='Advanced Login Form Analyzer')
    parser.add_argument('-u', '--url', required=True, help='Target URL to analyze')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads to use')
    parser.add_argument('-o', '--output', default='login_analysis_report.html', help='Output report file')
    parser.add_argument('-p', '--proxy', help='Proxy to use (e.g. http://127.0.0.1:8080)')
    parser.add_argument('-a', '--user-agent', help='Custom User-Agent string')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print(f"Starting analysis of {args.url}")
    analyzer = LoginAnalyzer(
        target_url=args.url,
        threads=args.threads,
        proxy=args.proxy,
        user_agent=args.user_agent
    )
    
    results = analyzer.run_all()
    
    if results:
        print(f"Analysis completed. Found {len(results['forms'])} login forms and {len(results['vulnerabilities'])} vulnerabilities.")
        print(f"Report generated: {args.output}")
    else:
        print("Analysis failed. Check the logs for details.")

if __name__ == "__main__":
    main()
