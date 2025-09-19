import os
import requests
import json
from dotenv import load_dotenv
import socket
import re

# Load environment variables
load_dotenv()
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
WHOISXML_KEY = os.getenv("WHOISXML_API_KEY")

# --- INTERNAL HELPER 1: IP Check ---
def is_ip(address: str) -> bool:
    """Helper function to check if a string is a valid IPv4 address."""
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", address):
        return True
    return False

# --- INTERNAL HELPER 2: IP Reputation (Called by our tools) ---
def _internal_ip_check(target: str) -> str:
    """Internal function to check IP/Domain rep. Returns a report string."""
    ip_to_check = ""
    if is_ip(target):
        ip_to_check = target
    else:
        try:
            ip_to_check = socket.gethostbyname(target)
        except socket.error:
            return f"Target '{target}' could not be resolved to an IP. Skipping."

    # Now we have a valid IP. Let's check it.
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip_to_check, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_KEY}
    
    try:
        response = requests.get(url=url, headers=headers, params=params)
        response.raise_for_status() 
        data = response.json()
        score = data['data']['abuseConfidenceScore']
        
        if score == 0:
            return f"Target {target} (IP: {ip_to_check}) appears CLEAN (Score: 0/100)."
        else:
            return f"WARNING: Target {target} (IP: {ip_to_check}) is MALICIOUS (Score: {score}/100)."
    except Exception:
        return f"Target {target} (IP: {ip_to_check}) could not be checked by AbuseIPDB. Skipping."


# --- AGENT TOOL 1: Find Subdomains ---
def find_subdomains(domain: str) -> str:
    """
    Use this tool FIRST to find subdomains for a single root domain. 
    It returns a single string containing a comma-separated list of subdomains.
    """
    print(f"--- TOOL 1 CALLED: find_subdomains({domain}) ---")
    url = 'https://subdomains.whoisxmlapi.com/api/v1'
    params = {'apiKey': WHOISXML_KEY, 'domainName': domain}
    
    try:
        response = requests.get(url=url, params=params)
        response.raise_for_status()
        data = response.json()
        subdomains = data.get('result', {}).get('records', [])
        if not subdomains:
            return f"No subdomains found for {domain}."
        
        domain_list = [record['domain'] for record in subdomains]
        # Return only the first 20 as a single comma-separated string
        return ", ".join(domain_list[:20])
    except Exception:
        return f"Error: Failed to find subdomains for {domain}."

# --- AGENT TOOL 2: Scan Domain List ---
def scan_subdomain_list(domain_list_string: str) -> str:
    """
    Use this tool SECOND, *after* you have a list of subdomains from 'find_subdomains'.
    This tool takes the comma-separated string of domains, checks each one,
    and returns a single, complete final report.
    """
    print(f"--- TOOL 2 CALLED: scan_subdomain_list(...) ---")
    # Split the input string back into a Python list
    subdomains_to_scan = domain_list_string.split(', ')
    
    final_report = [f"Recon Report: Starting scan on {len(subdomains_to_scan)} subdomains..."]
    malicious_count = 0
    
    # Python (free) does the loop, not the agent (expensive)
    for domain in subdomains_to_scan:
        report_line = _internal_ip_check(domain) # Call our internal helper
        if "WARNING" in report_line:
            malicious_count += 1
        final_report.append(report_line)
    
    # Add the final summary
    final_report.append("\n--- SCAN COMPLETE ---")
    final_report.append(f"Summary: Found {malicious_count} malicious targets.")
    
    # Return the whole report as one giant string
    return "\n".join(final_report)
    # --- INTERNAL HELPER 3: Port Scanner Helper ---
def _internal_port_scan(target_ip: str) -> str:
    """Internal helper to scan common ports on a single IP."""
    # We set a fast timeout so it doesn't hang for seconds on a closed port
    socket.setdefaulttimeout(0.5)
    common_ports = {
        21: "FTP",
        22: "SSH",
        80: "HTTP",
        443: "HTTPS (SSL)",
        3306: "MySQL",
        8080: "HTTP-Alt"
    }
    open_ports = []
    
    for port, service in common_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                # 0 means the port is OPEN
                open_ports.append(f"{port} ({service})")
            sock.close()
        except socket.error:
            pass # Ignore connection errors
            
    if not open_ports:
        return "No common ports open."
    else:
        return f"Open Ports found: [{', '.join(open_ports)}]"

# --- AGENT TOOL 3: Port Scan a List of Domains ---
def port_scan_domain_list(domain_list_string: str) -> str:
    """
    Use this tool THIRD. It takes the comma-separated list of domains,
    resolves their IPs, and scans each one for common open ports.
    It returns a single, complete port scan report.
    """
    print(f"--- TOOL 3 CALLED: port_scan_domain_list(...) ---")
    subdomains_to_scan = domain_list_string.split(', ')
    final_report = [f"Port Scan Report (scanning {len(subdomains_to_scan)} targets):"]
    
    for domain in subdomains_to_scan:
        try:
            ip_to_scan = socket.gethostbyname(domain)
            # Run our internal port scan function on the resolved IP
            port_report = _internal_port_scan(ip_to_scan)
            final_report.append(f"- {domain} (IP: {ip_to_scan}): {port_report}")
        except socket.error:
            final_report.append(f"- {domain}: [SKIPPED - Could not resolve IP]")
    
    final_report.append("\n--- PORT SCAN COMPLETE ---")
    return "\n".join(final_report)
# --- AGENT TOOL 4: Write Report to File ---
def write_report_to_file(report_content: str) -> str:
    """
    Use this tool LAST. It takes a single, large string (formatted as Markdown)
    and saves it to a file named 'FINAL_REPORT.md'.
    This is the final step of the mission.
    """
    print(f"--- TOOL 4 CALLED: write_report_to_file(...) ---")
    try:
        with open("FINAL_REPORT.md", "w", encoding="utf-8") as f:
            f.write(report_content)
        return "Successfully saved the report to FINAL_REPORT.md"
    except Exception as e:
        return f"Failed to save report: {e}"

# --- BLUE TEAM AGENT TOOLS ---

# This is the helper we already built, but we are also making it a standalone tool
# so the Blue Team agent can call it directly on any IP it finds.
def check_single_target_reputation(target: str) -> str:
    """
    Use this tool to check the reputation of a SINGLE target (IP or domain).
    It returns a clean, simple report for that one target.
    """
    print(f"--- BLUE TEAM TOOL CALLED: check_single_target_reputation({target}) ---")
    return _internal_ip_check(target) # This calls our existing helper function


# This is the path to the log file the user will upload.
LOG_FILE_PATH = "uploaded_log.log"

def search_log_file(search_query: str) -> str:
    """
    Use this tool to search the uploaded log file. 
    It takes a text search query (regex-compatible) and returns all matching lines,
    up to a maximum of 50 lines to avoid overwhelming the context.
    Example query: 'Failed password' or '404'
    """
    print(f"--- BLUE TEAM TOOL CALLED: search_log_file({search_query}) ---")
    try:
        with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        # Use regex to find all matching lines (case-insensitive)
        matching_lines = [line.strip() for line in lines if re.search(search_query, line, re.IGNORECASE)]
        
        if not matching_lines:
            return f"No matches found in log for query: '{search_query}'"
        
        # Limit the response to avoid flooding the agent's brain
        if len(matching_lines) > 50:
            summary = f"Found {len(matching_lines)} matches. Showing first 50.\n"
            summary += "\n".join(matching_lines[:50])
            return summary
        else:
            return f"Found {len(matching_lines)} matches:\n" + "\n".join(matching_lines)

    except FileNotFoundError:
        return "ERROR: No log file has been uploaded yet. Tell the user to upload a file first."
    except Exception as e:
        return f"Error during search: {e}"    