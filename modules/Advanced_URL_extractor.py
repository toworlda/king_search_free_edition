import os
import re
import sys
import html
import random
import warnings
import argparse
import string
import hashlib
import subprocess
import scrapy
import shutil
import threading
import logging
import requests
import multiprocessing
import asyncio
import aiohttp
import lxml
import pandas as pd
from tqdm import tqdm
from html import escape
from bs4 import BeautifulSoup
from bs4 import XMLParsedAsHTMLWarning
from urllib.parse import urlparse, urlunparse, unquote, urljoin
from typing import List, Tuple, Dict, Union, Optional, Any
from datetime import datetime
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

# Suppress unnecessary warnings
warnings.filterwarnings("ignore", category=UserWarning, module="bs4")
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# Configure logging with color support
class ColoredFormatter(logging.Formatter):
    """Colored formatter for better visual feedback"""
    COLORS = {
        'DEBUG': '\033[94m',    # Blue
        'INFO': '\033[92m',     # Green
        'WARNING': '\033[93m',  # Yellow
        'ERROR': '\033[91m',    # Red
        'CRITICAL': '\033[91m\033[1m',  # Bold Red
        'ENDC': '\033[0m',      # Reset
    }

    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.COLORS['ENDC']}"
        return super().format(record)

# Setup colored logging
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter("%(asctime)s - %(levelname)s - %(message)s", 
                                     datefmt="%Y-%m-%d %H:%M:%S"))
logger = logging.getLogger()
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Enhanced URL Categorization Patterns
CATEGORY_PATTERNS = {
    "API Endpoint": [
        r'/api/v?\d*/*',
        r'/rest/',
        r'/graphql',
        r'/gql',
        r'/swagger',
        r'/openapi',
        r'/endpoint',
    ],
    "Login Page": [
        r'/login',
        r'/signin',
        r'/auth',
        r'/authenticate',
        r'/session',
        r'/user/login',
        r'/account/login',
    ],
    "Sensitive Data": [
        r'/password',
        r'/secret',
        r'/token',
        r'/key',
        r'/credential',
        r'/private',
        r'/conf',
        r'/config',
        r'/account',
        r'/certificate',
    ],
    "Database Connection": [
        r'/db/',
        r'/database',
        r'/mysql',
        r'/postgres',
        r'/mongodb',
        r'/sqlite',
        r'/oracle',
        r'/sqlserver',
        r'/phpmyadmin',
        r'/adminer',
    ],
    "Payment": [
        r'/payment',
        r'/checkout',
        r'/cart',
        r'/order',
        r'/transaction',
        r'/billing',
        r'/invoice',
        r'/purchase',
        r'/buy',
    ],
    "Debug/Logging": [
        r'/debug',
        r'/log',
        r'/logs',
        r'/trace',
        r'/status',
        r'/health',
        r'/monitoring',
        r'/error',
        r'/exception',
    ],
    "User Data": [
        r'/user',
        r'/profile',
        r'/account',
        r'/member',
        r'/customer',
        r'/client',
        r'/contact',
    ],
    "Legacy Systems": [
        r'/old',
        r'/backup',
        r'/archive',
        r'/legacy',
        r'/deprecated',
        r'/v1/',
        r'/beta',
        r'/test',
    ]
}

# URL Deduplication Cache
URL_CACHE = set()
SEEN_HASHES = set()

@lru_cache(maxsize=20000)
def clean_and_validate_url(url):
    """
    Comprehensive URL cleaning and validation with caching for speed.
    
    Args:
        url (str): Raw URL to clean and validate
    
    Returns:
        str or None: Cleaned and validated URL, or None if invalid
    """
    try:
        # Handle string conversion if needed
        if not isinstance(url, str):
            url = str(url)
            
        # Generate hash for quick comparison before full processing
        url_hash = hashlib.md5(url.encode()).hexdigest()
        if url_hash in SEEN_HASHES:
            return None
        SEEN_HASHES.add(url_hash)
            
        # Remove noise
        url = url.strip("'\",:;.!?")
        
        # Decode HTML and URL entities
        url = html.unescape(url)
        url = unquote(url)
        
        # Strip whitespace and remove fragments
        url = url.strip().split("#")[0]
        
        # Remove unnecessary characters
        url = re.sub(r'[\'"\]\[<>]', '', url)
        
        # Check if URL is empty after cleaning
        if not url:
            return None
            
        # Parse URL to check validity
        parsed = urlparse(url)
        
        # Ensure URL has a valid scheme (http/https), else add "https://"
        if not parsed.scheme:
            url = "https://" + url.lstrip('/')
            parsed = urlparse(url)  # Re-parse after adding scheme
            
        # Ensure it's a valid URL with a domain name (no %, :, @)
        if not parsed.netloc or any(char in parsed.netloc for char in ['%', '@']):
            return None
            
        # Skip URLs ending with image extensions
        if parsed.path.lower().endswith((
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", 
            ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", 
            ".avi", ".mkv", ".webm", ".mov", ".flv", ".wmv", ".pdf"
        )):
            return None
            
        # Reconstruct URL
        clean_url = urlunparse(parsed)
        
        # Check if it's already in our global cache
        if clean_url in URL_CACHE:
            return None
        
        # Add to global cache
        URL_CACHE.add(clean_url)
        
        return clean_url
        
    except Exception as e:
        logging.debug(f"Error validating URL {url}: {str(e)}")
        return None

def extract_urls_from_text(content):
    """
    Extract URLs from text content using improved regex patterns for higher accuracy.
    
    Args:
        content (str): Text content to extract URLs from
        
    Returns:
        list: List of extracted URLs
    """
    # Skip if content is too small
    if not content or len(content) < 10:
        return []
        
    # Comprehensive URL regex pattern
    url_pattern = re.compile(
        r'(?:https?:)?\/\/(?:www\.)?'  # Protocol (optional)
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # Domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
        r'(?::\d+)?'  # Port
        r'(?:/?|[/?]\S+)$'
        r'(?:\?[^\s"\'<>(){}[\]]*)?'
        r'(?:#[^\s"\'<>(){}[\]]*)?',
        re.IGNORECASE
    )
    
    # Alternative pattern for URLs without protocol
    alt_pattern = re.compile(
        r'(?:^|\s+)(?:www\.)(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?))'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)'
        r'(?:/[^/\s]*)*'
        r'(?:\?[^\s"\'<>(){}[\]]*)?'
        r'(?:#[^\s"\'<>(){}[\]]*)?',
        re.IGNORECASE
    )
    
    # Extract URLs from content using both patterns
    raw_urls = set()
    raw_urls.update(url_pattern.findall(content))
    
    # Add www URLs (converting to proper format)
    for www_url in alt_pattern.findall(content):
        raw_urls.add('https://' + www_url.strip())
    
    # Extract potential URLs from attributes/strings
    attr_patterns = [
        r'(?:"|\'|\()(?:https?://|www\.)(?:[^\s"\'<>(){}\[\]]*)(?:"|\'|\))',
        r'href\s*=\s*["\']((?:https?:)?//[^"\'<>]*)["\']',
        r'src\s*=\s*["\']((?:https?:)?//[^"\'<>]*)["\']',
        r'url\s*\(\s*["\']((?:https?:)?//[^"\'<>]*)["\']',
        r'href\s*=\s*["\']((?:https?:)?//[^"\'<>]*|(?:https?:)?/[^"\'<>]*|www\.[^"\'<>]*)["\']',
        r'src\s*=\s*["\']((?:https?:)?//[^"\'<>]*|(?:https?:)?/[^"\'<>]*|www\.[^"\'<>]*)["\']',
        r'action\s*=\s*["\']((?:https?:)?//[^"\'<>]*|(?:https?:)?/[^"\'<>]*|www\.[^"\'<>]*)["\']',
        r'url\s*\(\s*["\']?((?:https?:)?//[^"\'<>()]*|(?:https?:)?/[^"\'<>()]*|www\.[^"\'<>()]*)["\']?\s*\)',
        r'data-\w+\s*=\s*["\']((?:https?:)?//[^"\'<>]*|(?:https?:)?/[^"\'<>]*|www\.[^"\'<>]*)["\']',
        r'content\s*=\s*["\'][^"\']*(?:https?:)?//[^"\'<>]*["\']',
        r'["\']((?:https?:)?//[^"\'<>]{5,}|(?:https?:)?/[^"\'<>]{5,}|www\.[^"\'<>]{5,})["\']'
    ]
    
    for pattern in attr_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            # Clean up the extracted URL
            url = match.strip("\"'()").split("#")[0]
            if url:
                raw_urls.add(url)
    
    # Process URLs in parallel with thread pool
    with ThreadPoolExecutor(max_workers=min(200, os.cpu_count() * 8)) as executor:
        valid_urls = list(filter(None, executor.map(clean_and_validate_url, raw_urls)))
    
    return valid_urls

# Completion of the extract_urls_from_html function
def extract_urls_from_html(file_path):
    """
    Enhanced extraction of URLs from HTML files with improved BeautifulSoup parsing.
    
    Args:
        file_path (str): Path to HTML file
        
    Returns:
        list: List of extracted URLs
    """
    try:
        # Read file content
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
        # Skip parsing if file is too small
        if len(content) < 10:
            return []
            
        # Parse with BeautifulSoup, using a faster parser when available
        try:
            soup = BeautifulSoup(content, "lxml")
        except:
            soup = BeautifulSoup(content, "html.parser")
            
        # Extract base URL if present
        base_url = ""
        base_tag = soup.find("base", href=True)
        if base_tag:
            base_url = base_tag["href"]
            
        # Initialize URL set
        raw_urls = set()
        
        # Expanded attribute mapping for more comprehensive extraction
        url_attributes = {
            "a": ["href", "data-url", "data-href"],
            "img": ["src", "data-src", "data-original", "data-url", "srcset"],
            "script": ["src", "data-src"],
            "link": ["href"],
            "iframe": ["src", "data-src"],
            "form": ["action", "data-action"],
            "meta": ["content"],  # For redirects
            "video": ["src", "poster"],
            "audio": ["src"],
            "source": ["src", "srcset"],
            "embed": ["src"],
            "object": ["data"],
            "area": ["href"],
            "button": ["formaction"],
            "input": ["formaction", "src"],
            "div": ["data-url", "data-href", "data-src"],
            "param": ["value"],
            "applet": ["code", "codebase"],
            "base": ["href"]
        }
        
        # Extract URLs from all specified tags/attributes
        for tag_name, attrs in url_attributes.items():
            for tag in soup.find_all(tag_name):
                for attr in attrs:
                    if tag.get(attr):
                        url = tag[attr].strip()
                        if url:
                            # Handle srcset attribute specially
                            if attr == "srcset":
                                for srcset_url in re.findall(r'([^\s,]+)', url):
                                    if base_url and not bool(urlparse(srcset_url).netloc):
                                        url = urljoin(base_url, srcset_url)
                                    raw_urls.add(srcset_url)
                            else:
                                # Handle relative URLs
                                if base_url and not bool(urlparse(url).netloc):
                                    url = urljoin(base_url, url)
                                raw_urls.add(url)
        
        # Extract inline scripts and CSS for deeper URL analysis
        for script in soup.find_all(["script", "style"]):
            if script.string:
                # Extract URLs from JavaScript and CSS
                js_urls = re.findall(
                    r'(?:"|\'|\()(?:https?://|www\.)(?:[^\s"\'<>(){}\[\]]*?)(?:"|\'|\))',
                    script.string
                )
                for url in js_urls:
                    url = url.strip("\"'()")
                    if url:
                        raw_urls.add(url)
        
        # Extract URLs from inline styles
        for tag in soup.find_all(style=True):
            # Extract URLs from style attributes
            style_urls = re.findall(r'url\(([^)]+)\)', tag['style'])
            for url in style_urls:
                url = url.strip("\"'")
                if base_url and not bool(urlparse(url).netloc):
                    url = urljoin(base_url, url)
                raw_urls.add(url)
                
        # Also extract from raw HTML text for anything we might have missed
        text_urls = extract_urls_from_text(content)
        raw_urls.update(text_urls)
        
        # Process URLs in parallel with thread pool
        with ThreadPoolExecutor(max_workers=min(200, os.cpu_count() * 8)) as executor:
            valid_urls = list(filter(None, executor.map(clean_and_validate_url, raw_urls)))
        
        return valid_urls
        
    except Exception as e:
        logging.error(f"Error extracting URLs from {file_path}: {str(e)}")
        return []

def process_file(file_path):
    """
    Process a single file to extract URLs.
    
    Args:
        file_path (str): Path to the file
        
    Returns:
        list: Extracted valid URLs
    """
    try:
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # Process HTML files
        if file_ext in [".html", ".htm"]:
            return extract_urls_from_html(file_path)
            
        # Process text-based files
        else:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return extract_urls_from_text(content)
            
    except Exception as e:
        logging.error(f"Error processing file {file_path}: {str(e)}")
        return []

def extract_urls_from_files(file_paths, max_workers=None):
    """
    Extract URLs from multiple files in parallel.
    
    Args:
        file_paths (list): List of file paths
        max_workers (int, optional): Max number of workers
        
    Returns:
        list: Combined list of extracted URLs
    """
    if not max_workers:
        max_workers = min(len(file_paths), os.cpu_count() * 2)
        
    all_urls = []
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        for urls in executor.map(process_file, file_paths):
            all_urls.extend(urls)
            
    return all_urls

def scan_folder_for_files(folder_path):
    """
    Scan folder for files to process.
    
    Args:
        folder_path (str): Path to folder
        
    Returns:
        list: List of file paths
    """
    file_paths = []
    
    supported_extensions = [
        '.html', '.htm', '.txt', '.json', '.js', 
        '.log', '.xml', '.md', '.csv', '.php',
        '.asp', '.aspx', '.jsp', '.py', '.rb'
    ]
    
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_ext = os.path.splitext(file)[1].lower()
            if file_ext in supported_extensions:
                file_path = os.path.join(root, file)
                file_paths.append(file_path)
                
    return file_paths

def get_domain(url):
    """
    Extract domain from URL.
    
    Args:
        url (str): URL to extract domain from
        
    Returns:
        str: Domain name
    """
    parsed = urlparse(url)
    return parsed.netloc

def filter_urls_by_domain(urls, domain=None):
    """
    Filter URLs by domain if specified.
    
    Args:
        urls (list): List of URLs to filter
        domain (str, optional): Domain to filter by
        
    Returns:
        list: Filtered URLs
    """
    if not domain:
        return urls
        
    filtered_urls = []
    domain = domain.lower()
    
    for url in urls:
        try:
            url_domain = get_domain(url).lower()
            if domain in url_domain:
                filtered_urls.append(url)
        except:
            continue
            
    logging.info(f"Filtered {len(filtered_urls)} URLs for domain: {domain}")
    return filtered_urls

def filter_unique_urls(urls):
    """
    Optimized filtering of unique URLs.
    
    Args:
        urls (list): List of URLs
        
    Returns:
        list: List of unique URLs
    """
    # Use OrderedDict to maintain order while eliminating duplicates
    from collections import OrderedDict
    return list(OrderedDict.fromkeys(urls))

def filter_unique_domain_urls(urls):
    """
    Filter URLs to keep only one URL per domain.
    
    Args:
        urls (list): List of URLs
        
    Returns:
        list: List of URLs with unique domains
    """
    unique_urls = []
    domains_seen = set()
    
    for url in urls:
        try:
            domain = get_domain(url)
            if domain and domain not in domains_seen:
                domains_seen.add(domain)
                unique_urls.append(url)
        except:
            continue
            
    return unique_urls


async def check_url_status_async(url, session, timeout=15):
    """
    Check URL HTTP status asynchronously with improved error handling.
    
    Args:
        url (str): URL to check
        session (aiohttp.ClientSession): Aiohttp session
        timeout (int): Request timeout in seconds
        
    Returns:
        tuple: (url, status_code or error message)
    """
    try:
        # Ensure URL is valid
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return url, "Invalid"
            
        # Try HEAD request first
        try:
            async with session.head(url, allow_redirects=True, timeout=timeout) as response:
                if response.status in [405, 403, 406, 501]:
                    # Fall back to GET for servers that don't support HEAD
                    async with session.get(url, allow_redirects=True, timeout=timeout) as response:
                        return url, response.status
                return url, response.status
        except (aiohttp.ClientResponseError, aiohttp.ServerDisconnectedError):
            # If HEAD fails, try GET
            async with session.get(url, allow_redirects=True, timeout=timeout) as response:
                return url, response.status
                
    except asyncio.TimeoutError:
        return url, "Timeout"
    except Exception as e:
        return url, "Failed"

async def check_urls_status_batch(urls, batch_size=300, max_connections=300):
    """
    Check status of multiple URLs asynchronously in batches.
    
    Args:
        urls (list): List of URLs to check
        batch_size (int): Size of each batch
        max_connections (int): Maximum number of connections
        
    Returns:
        list: List of tuples (url, status)
    """
    # Deduplicate URLs to avoid redundant requests
    unique_urls = list(dict.fromkeys(urls))
    
    connector = aiohttp.TCPConnector(
        limit=max_connections,
        limit_per_host=10,
        force_close=True,
        ssl=False
    )
    
    # Headers to mimic browser request
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }
    
    timeout = aiohttp.ClientTimeout(total=20)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
        results = []
        total_batches = (len(unique_urls) + batch_size - 1) // batch_size
        
        # Process in batches to avoid memory issues
        for i in range(0, len(unique_urls), batch_size):
            batch = unique_urls[i:i+batch_size]
            tasks = [check_url_status_async(url, session) for url in batch]
            
            try:
                batch_results = await asyncio.gather(*tasks)
                results.extend(batch_results)
            except Exception as e:
                logging.error(f"Error processing batch: {str(e)}")
                results.extend([(url, "Error") for url in batch])
            
            logging.info(f"Processed batch {i//batch_size + 1}/{total_batches}")
            
        return results

def check_urls_status(urls):
    """
    Check status of URLs using async IO for better performance.
    
    Args:
        urls (list): List of URLs to check
        
    Returns:
        list: List of working URLs with status 200
    """
    if not urls:
        return []
        
    logging.info(f"Checking status of {len(urls)} URLs...")
    
    # Get or create event loop
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    # Run async checks
    results = loop.run_until_complete(check_urls_status_batch(urls))
    
    # Analyze results
    status_counts = {"200": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "Failed": 0, "Timeout": 0, "Skipped": 0}
    working_urls = []
    
    for url, status in results:
        if status == 200:
            working_urls.append(url)
            status_counts["200"] += 1
        elif isinstance(status, int):
            if 200 <= status < 300:
                status_counts["2xx"] += 1
                working_urls.append(url)  # Consider all 2xx as working
            elif 300 <= status < 400:
                status_counts["3xx"] += 1
            elif 400 <= status < 500:
                status_counts["4xx"] += 1
            elif 500 <= status < 600:
                status_counts["5xx"] += 1
        else:
            status_counts[str(status)] += 1

    # Log summary
    logging.info("Status code summary:")
    for code, count in status_counts.items():
        if count > 0:
            logging.info(f"  {code}: {count} URLs")
            
    return working_urls

def categorize_url(url):
    """
    Categorize URL based on patterns.
    
    Args:
        url (str): URL to categorize
        
    Returns:
        str: Category name
    """
    # Handle different input types
    if isinstance(url, (list, tuple)):
        url = url[0]  # Extract URL from tuple
    elif isinstance(url, dict):
        # Try to get URL from dictionary
        if 'url' in url:
            url = url['url']
        elif 'URL' in url:
            url = url['URL']
        else:
            for k, v in url.items():
                if isinstance(v, str) and ('http' in v or 'www.' in v):
                    url = v
                    break
    
    # Ensure URL is a string
    if not isinstance(url, str):
        return "General Web Page"
    
    # Continue with your existing pattern matching code
    for category, patterns in CATEGORY_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return category
    return "General Web Page"


def generate_html_report(valid_urls, file_path, domain=None):
    """
    Generate HTML report with categorized URLs.
    
    Args:
        valid_urls (list): List of valid URLs
        file_path (str): Original file path for naming
        domain (str, optional): Domain filter used
        
    Returns:
        str: Path to generated report
    """
    if not valid_urls:
        logging.warning("No valid URLs to report.")
        return None
        
    # Categorize URLs
    categorized_urls = {}
    for url_item in valid_urls:
        # Extract URL properly based on type
        if isinstance(url_item, (list, tuple)):
            url = url_item[0]  # Extract URL from tuple
        elif isinstance(url_item, dict):
            # Try to get URL from dictionary
            if 'url' in url_item:
                url = url_item['url']
            elif 'URL' in url_item:
                url = url_item['URL']
            else:
                # Try to find URL-like string in dict values
                url = None
                for k, v in url_item.items():
                    if isinstance(v, str) and ('http' in v or 'www.' in v):
                        url = v
                        break
                if url is None:
                    continue  # Skip if no URL found
        else:
            url = url_item
        
        # Ensure URL is a string
        if not isinstance(url, str):
            continue
            
        # Continue with your existing categorization
        category = categorize_url(url)
        if category not in categorized_urls:
            categorized_urls[category] = []
        categorized_urls[category].append(url)

    # Create reports directory
    reports_dir = "/root/king_search/Reports/Data"
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate filename
    base_name = os.path.splitext(os.path.basename(file_path))[0]
    domain_part = f"_{domain}" if domain else ""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(reports_dir, f"{base_name}{domain_part}_{timestamp}.html")
    
    # Create HTML report
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>URL Report {domain_part}</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #2c3e50; text-align: center; }}
        h2 {{ color: #3498db; border-bottom: 1px solid #eee; padding-bottom: 10px; margin-top: 30px; }}
        .summary {{ background-color: #f8f9fa; border-left: 4px solid #3498db; padding: 15px; margin: 20px 0; }}
        .category {{ margin-bottom: 30px; }}
        .url-list {{ list-style-type: none; padding-left: 0; }}
        .url-list li {{ margin-bottom: 10px; background-color: #f8f9fa; padding: 10px; border-radius: 4px; }}
        .url-list a {{ color: #2980b9; text-decoration: none; word-break: break-all; }}
        .url-list a:hover {{ text-decoration: underline; }}
        .stats {{ display: flex; justify-content: space-around; flex-wrap: wrap; margin: 20px 0; }}
        .stat-box {{ background-color: #ecf0f1; padding: 15px; border-radius: 5px; margin: 10px; flex: 1; min-width: 200px; text-align: center; }}
        .stat-number {{ font-size: 24px; font-weight: bold; color: #3498db; }}
        footer {{ text-align: center; margin-top: 50px; color: #7f8c8d; font-size: 0.9em; }}
        .search-bar {{ margin: 20px 0; display: flex; }}
        .search-bar input {{ flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 4px 0 0 4px; }}
        .search-bar button {{ padding: 10px 15px; background: #3498db; color: white; border: none; border-radius: 0 4px 4px 0; cursor: pointer; }}
        .filters {{ display: flex; margin: 15px 0; }}
        .filter {{ margin-right: 15px; padding: 5px 10px; background: #eee; border-radius: 15px; cursor: pointer; }}
        .filter.active {{ background: #3498db; color: white; }}
        #top-domains {{ margin-top: 30px; }}
        .domain-stat {{ display: flex; justify-content: space-between; padding: 10px; border-bottom: 1px solid #eee; }}
    </style>
</head>
<body>
    <h1>URL Report{' for ' + domain if domain else ''}</h1>
    
    <div class="summary">
        <p>This report contains {len(valid_urls)} unique valid URLs{' from domain ' + domain if domain else ''}.</p>
    </div>
    
    <div class="search-bar">
        <input type="text" id="urlSearch" placeholder="Search URLs..." onkeyup="filterURLs()">
        <button onclick="filterURLs()">Search</button>
    </div>

    <div class="filters">
        <div class="filter active" onclick="filterCategory('all')">All</div>
        {''.join(f'<div class="filter" onclick="filterCategory(&quot;{category}&quot;)">{category}</div>' for category in sorted(categorized_urls.keys()))}
    </div>

    <div class="stats">
        <div class="stat-box">
            <div class="stat-number">{len(valid_urls)}</div>
            <div>Total URLs</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{len(categorized_urls)}</div>
            <div>Categories</div>
        </div>
    </div>
''')

        # Write categorized URLs
        for category, urls in sorted(categorized_urls.items()):
            f.write(f'''
    <div class="category" data-category="{category}">
        <h2>{category} ({len(urls)})</h2>
        <ul class="url-list">
''')
            for url in sorted(urls):
                f.write(f'            <li><a href="{url}" target="_blank">{url}</a></li>\n')
            f.write('        </ul>\n    </div>\n')

        # Add JavaScript for filtering - Escape the $ in template literals with \\$
        f.write('''
    <script>
        function filterURLs() {
            const searchTerm = document.getElementById('urlSearch').value.toLowerCase();
            const links = document.querySelectorAll('.url-list li a');
            
            links.forEach(link => {
                const url = link.textContent.toLowerCase();
                const listItem = link.parentElement;
                
                if (url.includes(searchTerm)) {
                    listItem.style.display = '';
                } else {
                    listItem.style.display = 'none';
                }
            });
            
            // Update counts
            document.querySelectorAll('.category').forEach(category => {
                const visibleItems = category.querySelectorAll('.url-list li[style=""]').length;
                const heading = category.querySelector('h2');
                const categoryName = heading.textContent.split(' (')[0];
                heading.textContent = `${categoryName} (${visibleItems})`;
            });
        }
        
        function filterCategory(category) {
            const filters = document.querySelectorAll('.filter');
            filters.forEach(filter => filter.classList.remove('active'));
            event.target.classList.add('active');
            
            if (category === 'all') {
                document.querySelectorAll('.category').forEach(cat => cat.style.display = '');
            } else {
                document.querySelectorAll('.category').forEach(cat => {
                    if (cat.dataset.category === category) {
                        cat.style.display = '';
                    } else {
                        cat.style.display = 'none';
                    }
                });
            }
        }
    </script>
''')

        # Close HTML
        f.write(f'''
    <footer>
        <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </footer>
</body>
</html>
''')

    logging.info(f"HTML report saved to: {report_path}")
    return report_path


def process_input(input_path, target_domain=None, check_status=True, unique_domains=True):
    """
    Process input file or folder to extract, validate and check URLs with optimized performance.
    
    Args:
        input_path (str): Path to file or folder
        target_domain (str, optional): Domain to filter by
        check_status (bool): Whether to check HTTP status
        unique_domains (bool): Whether to keep only unique domains
        
    Returns:
        list: List of validated URLs
    """
    start_time = datetime.now()
    
    # Extract URLs from file or folder
    if os.path.isfile(input_path):
        valid_urls = process_file(input_path)
    elif os.path.isdir(input_path):
        # Get list of files to process
        file_paths = scan_folder_for_files(input_path)
        logging.info(f"Found {len(file_paths)} files to process")
        
        # Process files in parallel
        valid_urls = extract_urls_from_files(file_paths)
    else:
        logging.error(f"Invalid input path: {input_path}")
        return []
        
    logging.info(f"Extracted and validated {len(valid_urls)} URLs in {(datetime.now() - start_time).total_seconds():.2f} seconds")
    
    # Filter by domain if specified
    if target_domain:
        valid_urls = filter_urls_by_domain(valid_urls, target_domain)
        
    # Remove any duplicates
    valid_urls = filter_unique_urls(valid_urls)
    logging.info(f"Filtered to {len(valid_urls)} unique URLs")
        
    # Keep only unique domain URLs if requested
    if unique_domains:
        valid_urls = filter_unique_domain_urls(valid_urls)
        logging.info(f"Filtered to {len(valid_urls)} URLs with unique domains")
    
    # Check URL status if requested
    if check_status and valid_urls:
        valid_urls = check_urls_status(valid_urls)
        
    logging.info(f"Total processing time: {(datetime.now() - start_time).total_seconds():.2f} seconds")
    return valid_urls

def main():
    """
    Main function to run the script with progress indicators.
    """
    print("\n===== Advanced URL Processor (Optimized) =====\n")
    
    # Get input path
    input_path = input("Enter file or folder path: ").strip()
    if not os.path.exists(input_path):
        logging.error("Invalid path. Exiting.")
        sys.exit(1)
        
    # Get optional domain filter
    target_domain = input("Enter target domain (leave blank for all domains): ").strip()
    
    # Get processing options
    check_status = input("Check URL status? (y/n, default: y): ").strip().lower() != 'n'
    unique_domains = input("Keep only unique domains? (y/n, default: y): ").strip().lower() != 'n'
    create_report = input("Create HTML report? (y/n, default: y): ").strip().lower() != 'n'
    
    try:
        # Process URLs
        start_time = datetime.now()
        print("\nProcessing URLs... This may take a while for large inputs.")
        valid_urls = process_input(input_path, target_domain, check_status, unique_domains)
        
        if not valid_urls:
            logging.warning("No valid URLs found after processing.")
            return
            
        # Create report if requested
        if create_report:
            print("\nGenerating HTML report...")
            report_path = generate_html_report(valid_urls, input_path, target_domain)
        
        elapsed_time = (datetime.now() - start_time).total_seconds()
        print(f"\n===== Processing Complete in {elapsed_time:.2f} seconds =====")
        print(f"Found {len(valid_urls)} valid URLs")
        if create_report:
            print(f"HTML report: {report_path}")
        # print(f"Text file: {output_file}")
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
