"""
PhishGuard AI — Digital Forensics Module
Gathers critical metadata (IP, Geo, SSL, Ports) about malicious websites.
Used to assist law enforcement by creating an automated threat profile.
"""

import socket
import ssl
import json
import requests
from urllib.parse import urlparse
from datetime import datetime
import concurrent.futures

def get_ip(domain: str) -> str:
    """Resolve domain to an IPv4 address."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def get_geo(ip: str) -> dict:
    """Fetch Geo-location and ISP info using ip-api.com"""
    if not ip: return {}
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3.0)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                return {
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org")
                }
    except Exception as e:
        print(f"Forensics Geo Error: {e}")
    return {}

def check_port(ip: str, port: int) -> bool:
    """Check if a specific port is open."""
    if not ip: return False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            result = s.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False

def check_ssl(domain: str) -> dict:
    """Extract basic SSL certificate information."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=2.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                issuer_name = issuer.get('organizationName', issuer.get('commonName', 'Unknown'))
                return {
                    "issuer": issuer_name,
                    "notAfter": cert.get('notAfter')
                }
    except Exception as e:
        print(f"Forensics SSL Error: {e}")
        return None

def gather_forensics(url_or_domain: str) -> dict:
    """Gathers comprehensive forensic profile for a dangerous domain."""
    domain = urlparse(url_or_domain).netloc if '://' in url_or_domain else url_or_domain
    domain = domain.split(':')[0]
    
    if not domain: 
        return None
        
    print(f"🔍 Starting forensics gathering for: {domain}")
    
    ip = get_ip(domain)
    geo = get_geo(ip)
    
    open_ports = []
    ssl_info = None
    
    if ip:
        # Check ports concurrently to speed up the process
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            p80_fut = executor.submit(check_port, ip, 80)
            p443_fut = executor.submit(check_port, ip, 443)
            
            if p80_fut.result(): open_ports.append(80)
            if p443_fut.result(): open_ports.append(443)
            
        if 443 in open_ports:
            ssl_info = check_ssl(domain)
            
    forensics = {
        "domain": domain,
        "ip_address": ip,
        "geo_location": geo,
        "open_ports": open_ports,
        "ssl_certificate": ssl_info,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    print(f"✅ Forensics payload completed for {domain}")
    return forensics
