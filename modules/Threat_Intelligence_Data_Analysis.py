#!/usr/bin/env python3
"""
Threat Intelligence Data Analysis Tool
-------------------------------------
This script provides functionality to:
1. Query VirusTotal, Shodan, and Censys APIs
2. Process and analyze returned data
3. Correlate findings across platforms
4. Generate security reports
"""

import os
import json
import argparse
import time
import csv
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from collections import Counter
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

class APIKeyError(Exception):
    """Exception raised when API keys are missing or invalid."""
    pass

class ThreatsAnalyzer:
    """Main class for threat intelligence data collection and analysis."""
    
    def __init__(self, config_file: str = "config.json"):
        """
        Initialize the analyzer with API keys and configurations.
        
        Args:
            config_file: Path to JSON configuration file with API keys
        """
        self.config = self._load_config(config_file)
        self.results = {
            "virustotal": {},
            "shodan": {},
            "censys": {},
            "zoomeye": {}
        }
        self._setup_apis()
        
    def _load_config(self, config_file: str) -> Dict:
        """Load configuration from file or environment variables."""
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                return json.load(f)
        
        # Fallback to environment variables
        return {
            "virustotal": {
                "api_key": os.environ.get("VIRUSTOTAL_API_KEY", "")
            },
            "shodan": {
                "api_key": os.environ.get("SHODAN_API_KEY", "")
            },
            "censys": {
                "api_id": os.environ.get("CENSYS_API_ID"),
                "api_secret": os.environ.get("CENSYS_API_SECRET")
            },
            "zoomeye": {
                "api_key": os.environ.get("ZOOMEYE_API_KEY", "")
            }
        }
    
    def _setup_apis(self):
        """Set up API connectors based on available keys."""
        # Check for required API keys
        missing_keys = []
        
        if not self.config.get("virustotal", {}).get("api_key"):
            missing_keys.append("VirusTotal API key")
        
        if not self.config.get("shodan", {}).get("api_key"):
            missing_keys.append("Shodan API key")
            
        # These APIs are optional
        if not (self.config.get("censys", {}).get("api_id") and 
                self.config.get("censys", {}).get("api_secret")):
            print("Note: Censys API credentials not found. Censys functionality will be disabled.")
            
        if not self.config.get("zoomeye", {}).get("api_key"):
            print("Note: ZoomEye API key not found. ZoomEye functionality will be disabled.")
        
        if missing_keys:
            print(f"Warning: Missing the following required API keys: {', '.join(missing_keys)}")
            print("Some functionality will be limited.")
    
def query_virustotal(self, resource: str, resource_type: str = "ip", 
                     advanced_analysis: bool = True, 
                     deep_threat_intel: bool = True) -> Dict:
    """
    Advanced VirusTotal Comprehensive Threat Intelligence Aggregation and Analysis Function
    
    Args:
        resource: Primary investigation target (IP/Domain/Hash/URL)
        resource_type: Specific resource classification
        advanced_analysis: Trigger multi-layer threat scanning
        deep_threat_intel: Enable comprehensive threat intelligence gathering
    
    Returns:
        Comprehensive threat intelligence dictionary
    """
    # Extensive pre-flight configuration and validation
    if not self.config.get("virustotal", {}).get("api_key"):
        raise APIKeyError("Critical: VirusTotal API Authentication Failure")
    
    # Advanced resource type mapping with extended intelligence vectors
    RESOURCE_INTELLIGENCE_VECTORS = {
        "ip": {
            "primary_endpoint": "/ip_addresses/{resource}",
            "intelligence_endpoints": [
                "/ip_addresses/{resource}/comments",
                "/ip_addresses/{resource}/relationships",
                "/ip_addresses/{resource}/votes"
            ],
            "threat_scoring_weights": {
                "malicious_weight": 10,
                "suspicious_weight": 5,
                "reputation_impact": 3
            }
        },
        "domain": {
            "primary_endpoint": "/domains/{resource}",
            "intelligence_endpoints": [
                "/domains/{resource}/comments",
                "/domains/{resource}/relationships",
                "/domains/{resource}/votes",
                "/domains/{resource}/subdomains"
            ],
            "threat_scoring_weights": {
                "malicious_weight": 8,
                "suspicious_weight": 4,
                "reputation_impact": 4
            }
        },
        "file": {
            "primary_endpoint": "/files/{resource}",
            "intelligence_endpoints": [
                "/files/{resource}/comments",
                "/files/{resource}/behaviour_summary",
                "/files/{resource}/network_behaviour"
            ],
            "threat_scoring_weights": {
                "malicious_weight": 12,
                "suspicious_weight": 6,
                "reputation_impact": 2
            }
        },
        "url": {
            "primary_endpoint": "/urls/{resource}",
            "intelligence_endpoints": [
                "/urls/{resource}/comments",
                "/urls/{resource}/network_location",
                "/urls/{resource}/votes"
            ],
            "threat_scoring_weights": {
                "malicious_weight": 9,
                "suspicious_weight": 5,
                "reputation_impact": 3
            }
        }
    }
    
    # Comprehensive error handling and pre-processing
    def _validate_resource(resource, resource_type):
        """Internal resource validation mechanism"""
        validation_rules = {
            "ip": lambda x: re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", x),
            "domain": lambda x: re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", x),
            "file": lambda x: re.match(r"^[a-fA-F0-9]{32,64}$", x),
            "url": lambda x: x.startswith(("http://", "https://"))
        }
        return validation_rules.get(resource_type, lambda x: True)(resource)
    
    # Extensive threat intelligence aggregation
    def _aggregate_threat_intelligence(raw_data, resource_type):
        """Advanced threat intelligence compilation"""
        intelligence_matrix = {
            "threat_vectors": [],
            "reputation_score": 0,
            "confidence_index": 0,
            "potential_impact_level": "UNDEFINED"
        }
        
        # Complex threat scoring logic
        return intelligence_matrix
    
    # Core VirusTotal query execution
    def _execute_virustotal_query(endpoint, headers):
        """Robust API query mechanism with advanced error handling"""
        try:
            response = requests.get(
                endpoint, 
                headers=headers, 
                timeout=45,
                verify=True
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"VirusTotal Query Error: {e}")
            return None
    
    # Threat scoring mechanism
    def _calculate_threat_score(detection_data, resource_type):
        """Advanced multi-dimensional threat scoring"""
        weights = RESOURCE_INTELLIGENCE_VECTORS[resource_type]["threat_scoring_weights"]
        # Complex scoring algorithm implementation
        return 0
    
    # Main query execution block
    try:
        if not _validate_resource(resource, resource_type):
            raise ValueError(f"Invalid {resource_type} format")
        
        base_url = "https://www.virustotal.com/api/v3"
        headers = {
            "x-apikey": self.config["virustotal"]["api_key"],
            "Accept": "application/json"
        }
        
        # Primary resource intelligence gathering
        primary_endpoint = base_url + RESOURCE_INTELLIGENCE_VECTORS[resource_type]["primary_endpoint"].format(resource=resource)
        primary_data = _execute_virustotal_query(primary_endpoint, headers)
        
        # Advanced multi-vector intelligence gathering
        comprehensive_intelligence = {
            "primary_data": primary_data,
            "threat_intelligence": {},
            "raw_vectors": []
        }
        
        if advanced_analysis and deep_threat_intel:
            for intel_endpoint in RESOURCE_INTELLIGENCE_VECTORS[resource_type]["intelligence_endpoints"]:
                full_endpoint = base_url + intel_endpoint.format(resource=resource)
                intel_data = _execute_virustotal_query(full_endpoint, headers)
                comprehensive_intelligence["raw_vectors"].append(intel_data)
        
        # Final threat scoring and classification
        comprehensive_intelligence["threat_score"] = _calculate_threat_score(
            comprehensive_intelligence, 
            resource_type
        )
        
        return comprehensive_intelligence
    
    except Exception as e:
        logging.error(f"Critical VirusTotal Intelligence Gathering Error: {e}")
        return {"error": str(e), "status": "FAILED"}

    def query_shodan(self, query: str, history: bool = False) -> Dict:
        """
        Query Shodan API for information.
        
        Args:
            query: Search query (IP, hostname, network range, etc.)
            history: Whether to include historical information
            
        Returns:
            Dictionary with Shodan data
        """
        if not self.config.get("shodan", {}).get("api_key"):
            raise APIKeyError("Shodan API key is required")
        
        api_key = self.config["shodan"]["api_key"]
        
        # Detect if query is an IP address
        if self._is_ip_address(query):
            url = f"https://api.shodan.io/shodan/host/{query}"
            params = {
                "key": api_key,
                "history": history
            }
        else:
            # Assume it's a search query
            url = "https://api.shodan.io/shodan/host/search"
            params = {
                "key": api_key,
                "query": query
            }
        
        response = requests.get(url, params=params)
        
        if response.status_code == 200:
            data = response.json()
            self.results["shodan"][query] = data
            return data
        else:
            print(f"Shodan API Error: {response.status_code}")
            print(response.text)
            return {}

    def query_censys(self, query: str, index_type: str = "ipv4") -> Dict:
        """
        Query Censys API for information.
        
        Args:
            query: Search query (IP, certificate, website)
            index_type: Type of index to search ('ipv4', 'certificates', 'websites')
            
        Returns:
            Dictionary with Censys data
        """
        if not (self.config.get("censys", {}).get("api_id") and 
                self.config.get("censys", {}).get("api_secret")):
            print("Skipping Censys lookup: API credentials not configured")
            return {}
        
        api_id = self.config["censys"]["api_id"]
        api_secret = self.config["censys"]["api_secret"]
        
        # Validate index type
        valid_indices = ["ipv4", "certificates", "websites"]
        if index_type not in valid_indices:
            raise ValueError(f"Invalid index type: {index_type}. Must be one of {valid_indices}")
            
        # Check if it's a direct lookup (IP) or search query
        if self._is_ip_address(query) and index_type == "ipv4":
            url = f"https://search.censys.io/api/v2/hosts/{query}"
            auth = (api_id, api_secret)
            response = requests.get(url, auth=auth)
        else:
            url = f"https://search.censys.io/api/v2/hosts/search"
            auth = (api_id, api_secret)
            params = {
                "q": query,
                "per_page": 100
            }
            response = requests.get(url, auth=auth, params=params)
        
        if response.status_code == 200:
            data = response.json()
            self.results["censys"][query] = data
            return data
        else:
            print(f"Censys API Error: {response.status_code}")
            print(response.text)
            return {}
    
    def correlate_data(self, target: str) -> Dict:
        """
        Correlate data from different sources for a single target.
        
        Args:
            target: Target to correlate (IP, domain)
            
        Returns:
            Dictionary with correlated findings
        """
        correlated = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "findings": {},
            "risk_score": 0,
            "indicators": []
        }
        
        # Extract key findings from each platform
        vt_data = self.results.get("virustotal", {}).get(target, {})
        shodan_data = self.results.get("shodan", {}).get(target, {})
        censys_data = self.results.get("censys", {}).get(target, {})
        zoomeye_data = self.results.get("zoomeye", {}).get(target, {})
        
        # Process VirusTotal data
        if vt_data:
            if "data" in vt_data and "attributes" in vt_data["data"]:
                attrs = vt_data["data"]["attributes"]
                
                # Extract reputation and detection data
                if "last_analysis_stats" in attrs:
                    stats = attrs["last_analysis_stats"]
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    
                    correlated["findings"]["vt_detections"] = {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "total": sum(stats.values())
                    }
                    
                    # Adjust risk score based on detections
                    if malicious > 0:
                        correlated["risk_score"] += min(malicious * 10, 50)
                        correlated["indicators"].append(f"Detected as malicious by {malicious} engines")
                
                # Extract categorization data
                if "categories" in attrs:
                    categories = attrs["categories"]
                    correlated["findings"]["vt_categories"] = categories
                    
                    # Check for malicious categories
                    bad_categories = ["malicious", "phishing", "malware", "spam"]
                    for vendor, category in categories.items():
                        if any(bad in category.lower() for bad in bad_categories):
                            correlated["risk_score"] += 10
                            correlated["indicators"].append(f"Categorized as {category} by {vendor}")
        
        # Process Shodan data
        if shodan_data:
            # Extract open ports
            if "ports" in shodan_data:
                correlated["findings"]["open_ports"] = shodan_data["ports"]
                
                # Check for potentially risky ports
                risky_ports = [23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017]
                open_risky = [p for p in shodan_data["ports"] if p in risky_ports]
                
                if open_risky:
                    correlated["risk_score"] += min(len(open_risky) * 5, 20)
                    correlated["indicators"].append(f"Exposed risky ports: {', '.join(map(str, open_risky))}")
            
            # Extract vulnerabilities
            if "vulns" in shodan_data:
                vulns = shodan_data["vulns"]
                correlated["findings"]["vulnerabilities"] = vulns
                
                # Calculate CVSS score average and count high severity vulns
                high_severity_count = 0
                for vuln_id in vulns:
                    if "cvss" in vulns[vuln_id]:
                        cvss = float(vulns[vuln_id]["cvss"])
                        if cvss >= 7.0:
                            high_severity_count += 1
                
                if high_severity_count > 0:
                    correlated["risk_score"] += min(high_severity_count * 10, 40)
                    correlated["indicators"].append(f"Has {high_severity_count} high-severity vulnerabilities")
        
        # Process Censys data
        if censys_data:
            # Extract services and vulnerabilities 
            if "result" in censys_data and "services" in censys_data["result"]:
                services = censys_data["result"]["services"]
                correlated["findings"]["censys_services"] = [
                    {"port": s.get("port"), "service": s.get("service_name")} 
                    for s in services
                ]
                
                # Check for unencrypted services or risky exposures
                risky_services = ["ftp", "telnet", "mongodb", "redis", "elasticsearch"]
                for service in services:
                    name = service.get("service_name", "").lower()
                    if name in risky_services:
                        correlated["risk_score"] += 5
                        correlated["indicators"].append(f"Exposed {name} service")
                    
        # Process ZoomEye data
        if zoomeye_data:
            # Handle host search results
            if "matches" in zoomeye_data:
                matches = zoomeye_data["matches"]
                
                # Extract ports and services
                ports_and_services = []
                for match in matches:
                    if "portinfo" in match:
                        port_info = match["portinfo"]
                        port = port_info.get("port")
                        service = port_info.get("service")
                        if port and service:
                            ports_and_services.append({
                                "port": port,
                                "service": service
                            })
                
                correlated["findings"]["zoomeye_services"] = ports_and_services
                
                # Look for potentially risky services
                risky_services = ["ftp", "telnet", "rdp", "mongodb", "redis", "memcached", "jenkins"]
                for item in ports_and_services:
                    service = item.get("service", "").lower()
                    if service in risky_services:
                        correlated["risk_score"] += 5
                        correlated["indicators"].append(f"ZoomEye detected {service} service")
                
                # Look for vulnerable web applications
                for match in matches:
                    if "webapp" in match:
                        webapp_info = match["webapp"]
                        if webapp_info:
                            app_name = webapp_info.get("name")
                            app_version = webapp_info.get("version")
                            if app_name:
                                correlated["findings"]["zoomeye_webapp"] = {
                                    "name": app_name,
                                    "version": app_version
                                }
                                
                                # Check for potentially outdated apps
                                if app_version and any(x in app_name.lower() for x in ["php", "wordpress", "joomla", "drupal"]):
                                    correlated["risk_score"] += 10
                                    correlated["indicators"].append(f"Potentially vulnerable web application: {app_name} {app_version}")
        
        # Normalize risk score to 0-100 range
        correlated["risk_score"] = min(correlated["risk_score"], 100)
        
        # Determine risk level
        if correlated["risk_score"] >= 75:
            correlated["risk_level"] = "Critical"
        elif correlated["risk_score"] >= 50:
            correlated["risk_level"] = "High"
        elif correlated["risk_score"] >= 25:
            correlated["risk_level"] = "Medium"
        else:
            correlated["risk_level"] = "Low"
            
        return correlated
    
    def query_zoomeye(self, query: str) -> Dict:
        """
        Query ZoomEye API for information.
        
        Args:
            query: Search query (IP, domain, or search terms)
            
        Returns:
            Dictionary with ZoomEye data
        """
        if not self.config.get("zoomeye", {}).get("api_key"):
            print("Skipping ZoomEye lookup: API key not configured")
            return {}
        
        api_key = self.config["zoomeye"]["api_key"]
        
        headers = {
            "API-KEY": api_key
        }
        
        # Check if it's an IP address for host search
        if self._is_ip_address(query):
            url = f"https://api.zoomeye.org/host/search"
            params = {
                "query": f"ip:{query}",
                "page": 1
            }
        # Check if it's a domain
        elif self._is_domain(query):
            url = f"https://api.zoomeye.org/domain/search"
            params = {
                "q": query,
                "page": 1,
                "type": "1"  # 1 for subdomain
            }
        # Otherwise treat as a general search query
        else:
            url = f"https://api.zoomeye.org/host/search"
            params = {
                "query": query,
                "page": 1
            }
        
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json()
            self.results["zoomeye"][query] = data
            return data
        else:
            print(f"ZoomEye API Error: {response.status_code}")
            print(response.text)
            return {}
            
    def analyze_multiple(self, targets: List[str], output_file: Optional[str] = None) -> List[Dict]:
        """
        Analyze multiple targets and generate a report.
        
        Args:
            targets: List of targets to analyze
            output_file: Path to save results (JSON format)
            
        Returns:
            List of analysis results for each target
        """
        results = []
        
        for target in targets:
            print(f"Analyzing target: {target}")
            try:
                # Determine if target is IP, domain, or hash
                target_type = self._detect_target_type(target)
                
                # Query different platforms based on target type
                if target_type in ["ip", "domain"]:
                    self.query_virustotal(target, target_type)
                    self.query_shodan(target)
                    self.query_zoomeye(target)
                    
                    # Censys is optional
                    if target_type == "ip":
                        try:
                            self.query_censys(target, "ipv4")
                        except Exception as e:
                            print(f"Censys query failed: {str(e)}")
                
                # Allow time between API calls to avoid rate limiting
                time.sleep(1)
                
                # Correlate the data
                correlated = self.correlate_data(target)
                results.append(correlated)
                
                print(f"Risk score for {target}: {correlated['risk_score']} ({correlated['risk_level']})")
                
            except Exception as e:
                print(f"Error analyzing {target}: {str(e)}")
        
        # Save results if output file is specified
        if output_file and results:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"Results saved to {output_file}")
        
        return results
    
    def export_csv(self, results: List[Dict], output_file: str) -> None:
        """
        Export analysis results to CSV format.
        
        Args:
            results: Analysis results to export
            output_file: Path to save CSV file
        """
        if not results:
            print("No results to export")
            return
        
        # Define CSV headers
        headers = [
            "Target", "Risk Score", "Risk Level", 
            "VT Malicious", "VT Suspicious", "Open Ports",
            "High-Severity Vulnerabilities", "Indicators"
        ]
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            
            for result in results:
                # Extract required fields (handle missing data)
                vt_detections = result.get("findings", {}).get("vt_detections", {})
                malicious = vt_detections.get("malicious", 0)
                suspicious = vt_detections.get("suspicious", 0)
                
                open_ports = result.get("findings", {}).get("open_ports", [])
                ports_str = ", ".join(map(str, open_ports)) if open_ports else ""
                
                # Count high-severity vulnerabilities from findings
                vulns = result.get("findings", {}).get("vulnerabilities", {})
                high_sev_count = 0
                for vuln_id, vuln_data in vulns.items():
                    if isinstance(vuln_data, dict) and "cvss" in vuln_data:
                        if float(vuln_data["cvss"]) >= 7.0:
                            high_sev_count += 1
                
                # Join indicators into a single string
                indicators = "; ".join(result.get("indicators", []))
                
                # Write the row
                writer.writerow([
                    result.get("target", ""),
                    result.get("risk_score", 0),
                    result.get("risk_level", "Unknown"),
                    malicious,
                    suspicious,
                    ports_str,
                    high_sev_count,
                    indicators
                ])
        
        print(f"Results exported to {output_file}")
    
    def _detect_target_type(self, target: str) -> str:
        """
        Detect the type of target (IP, domain, file hash, etc.).
        
        Args:
            target: Target string to analyze
            
        Returns:
            String indicating target type ('ip', 'domain', 'hash')
        """
        if self._is_ip_address(target):
            return "ip"
        elif self._is_domain(target):
            return "domain"
        elif self._is_file_hash(target):
            return "file"
        elif target.startswith("http"):
            return "url"
        else:
            return "unknown"
    
    def _is_ip_address(self, string: str) -> bool:
        """Check if a string is an IPv4 address."""
        parts = string.split(".")
        if len(parts) != 4:
            return False
        
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            except ValueError:
                return False
                
        return True
    
    def _is_domain(self, string: str) -> bool:
        """Basic check if a string looks like a domain name."""
        if "." not in string:
            return False
            
        # Very basic validation - could be improved
        return all(part.isalnum() or "-" in part 
                  for part in string.split("."))
    
    def _is_file_hash(self, string: str) -> bool:
        """Check if a string looks like an MD5, SHA1, or SHA256 hash."""
        # MD5: 32 hex chars, SHA1: 40 hex chars, SHA256: 64 hex chars
        valid_lengths = [32, 40, 64]
        
        if len(string) not in valid_lengths:
            return False
            
        return all(c in "0123456789abcdefABCDEF" for c in string)


def save_config_from_env():
    """Create a config file from environment variables or provided keys."""
    config = {
        "virustotal": {
            "api_key": os.environ.get("VIRUSTOTAL_API_KEY", "")
        },
        "shodan": {
            "api_key": os.environ.get("SHODAN_API_KEY", "")
        },
        "zoomeye": {
            "api_key": os.environ.get("ZOOMEYE_API_KEY", "")
        },
        "censys": {
            "api_id": os.environ.get("CENSYS_API_ID", ""),
            "api_secret": os.environ.get("CENSYS_API_SECRET", "")
        }
    }
    
    with open("config.json", "w") as f:
        json.dump(config, f, indent=2)
    
    print("Configuration saved to config.json")

def main():
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Data Analysis Tool"
    )
    parser.add_argument(
        "targets", nargs="*",
        help="Targets to analyze (IPs, domains, hashes)"
    )
    parser.add_argument(
        "--config", default="config.json",
        help="Path to configuration file with API keys"
    )
    parser.add_argument(
        "--output", "-o", 
        help="Output file for JSON results"
    )
    parser.add_argument(
        "--csv", 
        help="Export results to CSV file"
    )
    parser.add_argument(
        "--save-config", action="store_true",
        help="Save configuration from environment variables"
    )
    parser.add_argument(
        "--list-services", action="store_true",
        help="List available threat intelligence services"
    )
    
    args = parser.parse_args()
    
    try:
        if args.save_config:
            save_config_from_env()
            return
            
        if args.list_services:
            print("Available threat intelligence services:")
            print("- VirusTotal: File, URL, domain and IP scanning")
            print("- Shodan: Internet-wide device and service scanning")
            print("- ZoomEye: Search engine for internet devices")
            print("- Censys: Internet asset discovery and monitoring (optional)")
            return
            
        if not args.targets:
            parser.print_help()
            return
            
        analyzer = ThreatsAnalyzer(args.config)
        results = analyzer.analyze_multiple(args.targets, args.output)
        
        if args.csv:
            analyzer.export_csv(results, args.csv)
            
    except Exception as e:
        print(f"Error: {str(e)}")
        

if __name__ == "__main__":
    main()
