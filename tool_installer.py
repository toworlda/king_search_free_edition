import os
import sys
import json
import shutil
import argparse
from pathlib import Path
import subprocess

# Define tool install methods
tools = {
    "nmap": "apt",
    "sqlmap": "apt",
    "nikto": "apt",
    "nuclei": "go",
    "whatweb": "apt",
    "ffuf": "go",
    "sslscan": "apt",
    "cewl": "apt",
    "gobuster": "apt",
    "hashcat": "apt",
    "katana": "go",
    "joomscan": "git",
    "dirsearch": "git",
    "dirb": "apt",
    "curl": "apt",
    "sublist3r": "git",
    "assetfinder": "go",
    "gau": "go",
    "waymore": "git",
    "waybackurls": "go",
    "httpx": "go",
    "theHarvester": "apt",
    "amass": "snap",
    "subfinder": "go",
    "anew": "go",
    "gf": "go",
    "qsreplace": "go",
    "dnsx": "go",
    "git": "apt",
    "grep": "apt",
}

git_urls = {
    "joomscan": "https://github.com/OWASP/joomscan.git",
    "dirsearch": "https://github.com/maurosoria/dirsearch.git",
    "sublist3r": "https://github.com/aboul3la/Sublist3r.git",
    "waymore": "https://github.com/xnl-h4ck3r/waymore.git",
}

go_install_map = {
    "nuclei": "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
    "ffuf": "github.com/ffuf/ffuf@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "assetfinder": "github.com/tomnomnom/assetfinder@latest",
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "anew": "github.com/tomnomnom/anew@latest",
    "gf": "github.com/tomnomnom/gf@latest",
    "qsreplace": "github.com/tomnomnom/qsreplace@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
}

HOME = str(Path.home())
GO_PATH = os.path.join(HOME, "go", "bin")
TOOLS_DIR = os.path.join(HOME, "king_search/Reports/tools")
dest = os.path.join(TOOLS_DIR)
os.makedirs(TOOLS_DIR, exist_ok=True)
tool_status = {}

def is_installed(tool):
    return shutil.which(tool) is not None

def run_command(command):
    print(f"[RUNNING] {command}")
    subprocess.run(command, shell=True, check=True)

def add_go_bin_to_path():
    bashrc = os.path.join(HOME, ".bashrc")
    path_export = f'\n# Added by tool_installer.py\nexport PATH="$PATH:{GO_PATH}"\n'

    with open(bashrc, "r") as f:
        bashrc_content = f.read()

    if GO_PATH not in bashrc_content:
        print("[+] Adding Go bin path to ~/.bashrc")
        with open(bashrc, "a") as f:
            f.write(path_export)
    else:
        print("[*] Go bin path already in ~/.bashrc")

def install_tool(tool, method, auto_install=False):
    if auto_install:
        print(f"[!] Auto-installing {tool} using {method}...")
    else:
        user_input = input(f"[?] {tool} is missing. Install using {method}? (y/n): ").strip().lower()
        if user_input != "y":
            print(f"[-] Skipping installation of {tool}.")
            tool_status[tool] = "missing"
            return

    try:
        if method == "apt":
            run_command(f"sudo apt-get install -y {tool}")
        elif method == "snap":
            run_command(f"sudo snap install {tool}")
        elif method == "go":
            if tool in go_install_map:
                run_command(f"go install {go_install_map[tool]}")
            else:
                print(f"[x] No go install mapping found for {tool}")
        elif method == "git":
            url = git_urls.get(tool)
            if url:
                dest = os.path.join(TOOLS_DIR, tool)
                os.makedirs(TOOLS_DIR, exist_ok=True)
                run_command(f"git clone {url} {dest}")

                # Special handling for runnable scripts
                if tool == "sublist3r":
                    run_command(f"pip3 install -r {dest}/requirements.txt")
                    os.symlink(os.path.join(dest, "sublist3r.py"), "/usr/local/bin/sublist3r")
                    run_command("chmod +x /usr/local/bin/sublist3r")
                elif tool == "dirsearch":
                    os.symlink(os.path.join(dest, "dirsearch.py"), "/usr/local/bin/dirsearch")
                    run_command("chmod +x /usr/local/bin/dirsearch")

                print(f"[+] {tool} installed and linked to /usr/local/bin/")
            else:
                print(f"[x] No git URL found for {tool}")
        else:
            print(f"[x] Unknown method '{method}' for tool '{tool}'")

        tool_status[tool] = "installed_now"

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to install {tool}: {e}")
        tool_status[tool] = "error"

def main():
    parser = argparse.ArgumentParser(description="Tool Checker and Installer")
    parser.add_argument("--check-only", action="store_true", help="Only check for tools, do not install.")
    parser.add_argument("--auto-install", action="store_true", help="Automatically install missing tools without prompting.")
    args = parser.parse_args()

    print("[*] Starting tool check and installation...\n")
    for tool, method in tools.items():
        if is_installed(tool):
            print(f"[+] {tool} is already installed.")
            tool_status[tool] = "installed"
        else:
            if args.check_only:
                print(f"[-] {tool} is missing.")
                tool_status[tool] = "missing"
            else:
                install_tool(tool, method, auto_install=args.auto_install)

    if not args.check_only:
        add_go_bin_to_path()

    print("\n[*] Tool check complete. Generating status report...")
    report_path = os.path.join(HOME, "tool_status.json")
    with open(report_path, "w") as f:
        json.dump(tool_status, f, indent=4)
    print(f"[+] Status report saved to {report_path}.")
    print("[*] Installation complete. Restart terminal or run 'source ~/.bashrc' to apply PATH changes.")

if __name__ == "__main__":
    main()
