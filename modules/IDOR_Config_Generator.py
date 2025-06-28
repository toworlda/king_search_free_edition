#!/usr/bin/env python3
"""
IDOR Config Generator

This script helps generate configuration for the IDOR Tester from existing
credential files or from URLs discovered during reconnaissance.

Usage:
    python3 generate_config.py --creds-file creds.json --output config.json
    python3 generate_config.py --url-file urls.txt --output config.json
"""

import argparse
import json
import re
import base64
import sys
import urllib.parse
from typing import Dict, List, Any

def parse_user_id_from_url(url: str) -> str:
    """
    Attempts to extract user IDs from URLs using common patterns
    """
    # Common patterns for user IDs in URLs
    patterns = [
        r'/users?/([a-zA-Z0-9_-]+)',
        r'/profiles?/([a-zA-Z0-9_-]+)',
        r'/accounts?/([a-zA-Z0-9_-]+)',
        r'user_?id=([a-zA-Z0-9_-]+)',
        r'uid=([a-zA-Z0-9_-]+)',
        r'id=([a-zA-Z0-9_-]+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    
    return None

def extract_path_params(url: str) -> List[str]:
    """
    Extract parameters from path segments in URL
    """
    parsed_url = urllib.parse.urlparse(url)
    path_segments = parsed_url.path.split('/')
    
    # Find segments that look like IDs or parameters
    potential_ids = []
    for segment in path_segments:
        # Check if segment looks like an ID (alphanumeric, no special chars except dash/underscore)
        if re.match(r'^[a-zA-Z0-9_-]+$', segment) and len(segment) > 3:
            potential_ids.append(segment)
    
    return potential_ids

def extract_query_params(url: str) -> Dict[str, str]:
    """
    Extract query parameters from URL
    """
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    # Convert lists to single values
    return {k: v[0] for k, v in query_params.items()}

def parse_credentials_file(file_path: str) -> Dict[str, Any]:
    """
    Parse the credentials file containing basic_auth and bearer tokens
    """
    with open(file_path, 'r') as f:
        try:
            creds_data = json.load(f)
            return creds_data
        except json.JSONDecodeError:
            print(f"Error: {file_path} is not a valid JSON file")
            sys.exit(1)

def parse_urls_file(file_path: str) -> List[str]:
    """
    Parse file containing URLs, one per line
    """
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def generate_config_from_creds(creds_data: Dict[str, Any], output_file: str):
    """
    Generate IDOR tester config file from credentials data
    """
    config = {
        "credentials": [],
        "target_endpoints": [],
        "valid_urls": [],
        "test_parameters": {
            "threads": 10,
            "timeout": 15,
            "retry_attempts": 3,
            "delay_between_requests": 0.5,
            "follow_redirects": True,
            "verify_ssl": False
        }
    }
    
    # Extract credentials
    if isinstance(creds_data, list):
        for cred in creds_data:
            if isinstance(cred, dict) and "type" in cred:
                config["credentials"].append(cred)
                
                # Extract valid URLs if present
                if "valid_urls" in cred and isinstance(cred["valid_urls"], list):
                    for url_entry in cred["valid_urls"]:
                        if isinstance(url_entry, dict) and "url" in url_entry:
                            # Add to valid URLs if not already present
                            if url_entry not in config["valid_urls"]:
                                config["valid_urls"].append(url_entry)
                            
                            # Generate target endpoints based on valid URLs
                            url = url_entry["url"]
                            user_id = parse_user_id_from_url(url)
                            
                            if user_id:
                                # Create endpoint with identified user_id
                                endpoint = {
                                    "url": url.replace(user_id, "{user_id}"),
                                    "method": "GET",
                                    "original_ids": [user_id],
                                    "target_ids": ["admin", "root", "administrator", "12345"],
                                    "id_locations": ["url"],
                                    "success_indicators": ["\"username\":", "\"email\":", "\"profile\":", "\"id\":"],
                                    "success_status_codes": [200, 201, 202]
                                }
                                
                                # Check if this endpoint is already in the list (avoid duplicates)
                                if not any(e["url"] == endpoint["url"] for e in config["target_endpoints"]):
                                    config["target_endpoints"].append(endpoint)
    
    # Write the config to file
    with open(output_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"Configuration generated at {output_file}")
    print(f"- {len(config['credentials'])} credentials")
    print(f"- {len(config['valid_urls'])} valid URLs")
    print(f"- {len(config['target_endpoints'])} target endpoints")

def generate_config_from_urls(urls: List[str], output_file: str):
    """
    Generate IDOR tester config file from URLs
    """
    config = {
        "credentials": [
            {
                "type": "basic_auth",
                "value": "dGVzdDp0ZXN0", # test:test
                "decoded": "test:test",
                "username": "test",
                "password": "test"
            }
        ],
        "target_endpoints": [],
        "valid_urls": [],
        "test_parameters": {
            "threads": 10,
            "timeout": 15,
            "retry_attempts": 3,
            "delay_between_requests": 0.5,
            "follow_redirects": True,
            "verify_ssl": False
        }
    }
    
    # Process each URL
    for url in urls:
        # Add to valid URLs
        config["valid_urls"].append({
            "url": url,
            "status_code": 200,
            "content_length": 0,
            "title": None
        })
        
        # Extract potential user IDs
        user_id = parse_user_id_from_url(url)
        path_params = extract_path_params(url)
        query_params = extract_query_params(url)
        
        # If we found a user ID in the URL
        if user_id:
            endpoint = {
                "url": url.replace(user_id, "{user_id}"),
                "method": "GET",
                "original_ids": [user_id],
                "target_ids": ["admin", "root", "administrator", "12345"],
                "id_locations": ["url"],
                "success_indicators": ["\"username\":", "\"email\":", "\"profile\":", "\"id\":"],
                "success_status_codes": [200, 201, 202]
            }
            
            # Check if this endpoint is already in the list (avoid duplicates)
            if not any(e["url"] == endpoint["url"] for e in config["target_endpoints"]):
                config["target_endpoints"].append(endpoint)
        
        # If we found potential ID parameters in the query string
        for param, value in query_params.items():
            if any(id_keyword in param.lower() for id_keyword in ["id", "user", "account", "uid"]):
                # Create endpoint with parameter replacement
                parsed_url = urllib.parse.urlparse(url)
                query_dict = urllib.parse.parse_qs(parsed_url.query)
                
                # Remove the target parameter from query string (we'll add it back in params_template)
                if param in query_dict:
                    original_value = query_dict[param][0]
                    del query_dict[param]
                    
                    # Rebuild URL without this parameter
                    new_query = urllib.parse.urlencode(query_dict, doseq=True)
                    new_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        new_query,
                        parsed_url.fragment
                    ))
                    
                    endpoint = {
                        "url": new_url,
                        "method": "GET",
                        "original_ids": [original_value],
                        "target_ids": ["admin", "root", "administrator", "12345"],
                        "id_locations": ["params"],
                        "params_template": {
                            param: "{user_id}"
                        },
                        "success_indicators": ["\"username\":", "\"email\":", "\"profile\":", "\"id\":"],
                        "success_status_codes": [200, 201, 202]
                    }
                    
                    if not any(e["url"] == endpoint["url"] and 
                               e.get("params_template", {}).get(param) == "{user_id}" 
                               for e in config["target_endpoints"]):
                        config["target_endpoints"].append(endpoint)
    
    # If we couldn't generate any endpoints, add some defaults
    if not config["target_endpoints"]:
        print("Warning: Couldn't identify any user IDs in the provided URLs.")
        print("Adding some common endpoint patterns to try.")
        
        # Get base domains from URLs
        domains = set()
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            domains.add(f"{parsed.scheme}://{parsed.netloc}")
        
        # Add common API endpoints for each domain
        for domain in domains:
            config["target_endpoints"].extend([
                {
                    "url": f"{domain}/api/users/{{user_id}}",
                    "method": "GET",
                    "original_ids": ["1", "self"],
                    "target_ids": ["admin", "2", "root"],
                    "id_locations": ["url"],
                    "success_indicators": ["\"username\":", "\"email\":", "\"profile\":", "\"id\":"],
                    "success_status_codes": [200]
                },
                {
                    "url": f"{domain}/api/accounts/{{user_id}}/profile",
                    "method": "GET",
                    "original_ids": ["1", "self"],
                    "target_ids": ["admin", "2", "root"],
                    "id_locations": ["url"],
                    "success_indicators": ["\"username\":", "\"email\":", "\"profile\":", "\"id\":"],
                    "success_status_codes": [200]
                }
            ])
    
    # Write the config to file
    with open(output_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"Configuration generated at {output_file}")
    print(f"- {len(config['credentials'])} credentials")
    print(f"- {len(config['valid_urls'])} valid URLs")
    print(f"- {len(config['target_endpoints'])} target endpoints")

def main():
    parser = argparse.ArgumentParser(description='Generate IDOR Tester Configuration')
    parser.add_argument('--creds-file', help='Path to credentials JSON file')
    parser.add_argument('--url-file', help='Path to file containing URLs (one per line)')
    parser.add_argument('--output', required=True, help='Path to output configuration file')
    
    args = parser.parse_args()
    
    if args.creds_file:
        creds_data = parse_credentials_file(args.creds_file)
        generate_config_from_creds(creds_data, args.output)
    elif args.url_file:
        urls = parse_urls_file(args.url_file)
        generate_config_from_urls(urls, args.output)
    else:
        print("Error: Either --creds-file or --url-file must be specified")
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()
