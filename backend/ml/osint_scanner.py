"""
PhishGuard AI — Automated OSINT Scanner
Background worker that fetches global phishing feeds (e.g. OpenPhish),
gathers forensics data (IP, Geo, ISP), and saves to the MVD Threat Intel Dashboard.
"""

import time
import json
import threading
import requests
from typing import List

# Import from the application context
# We use deferred imports for some modules inside functions to prevent circular dependencies if they exist
from ml.forensics import gather_forensics

# Limit the number of domains processed per cycle to prevent overwhelming the server/APIs
MAX_NEW_DOMAINS_PER_CYCLE = 20
SCAN_INTERVAL_SECONDS = 3600  # 1 hour

_scanner_thread = None
_stop_event = threading.Event()

def get_openphish_list() -> List[str]:
    """Fetches the latest openphish public feed."""
    try:
        resp = requests.get('https://openphish.com/feed.txt', timeout=10.0)
        if resp.status_code == 200:
            domains = []
            for line in resp.text.split('\n'):
                line = line.strip()
                if line:
                    # OpenPhish provides full URLs, we only want the domain for the dashboard tracking initially
                    from urllib.parse import urlparse
                    try:
                        parsed = urlparse(line)
                        if parsed.netloc:
                            domain = parsed.netloc.lower().split(':')[0]
                            if domain not in domains:
                                domains.append(domain)
                        else:
                            # if no scheme, it might just be the domain
                            parts = line.split('/')
                            domain = parts[0].split(':')[0].lower()
                            if domain and domain not in domains:
                                domains.append(domain)
                    except Exception:
                        pass
            print(f"OSINT Scanner: Fetched {len(domains)} unique domains from OpenPhish.")
            return domains
    except Exception as e:
        print(f"OSINT Scanner: Failed to fetch OpenPhish: {e}")
    return []

def process_threats(domains: List[str]):
    """Process a list of malicious domains, gather forensics, and save."""
    from database import SessionLocal, DangerousDomain, save_dangerous_domain
    
    db = SessionLocal()
    try:
        processed_count = 0
        
        for domain in domains:
            if processed_count >= MAX_NEW_DOMAINS_PER_CYCLE:
                break
                
            # Quick check if it already exists to avoid heavy forensics call
            existing = db.query(DangerousDomain).filter(DangerousDomain.domain == domain).first()
            if existing:
                continue
                
            print(f"OSINT Scanner: Processing new threat - {domain}")
            
            # Gather forensics (IP, Geo, SSL)
            forensics_data = None
            try:
                f_dict = gather_forensics(domain)
                if f_dict:
                    # Sometimes IP resolution fails (domain taken down), we still save it but just to track it
                    forensics_data = json.dumps(f_dict)
            except Exception as e:
                print(f"OSINT Scanner: Forensics error for {domain} - {e}")
            
            # Save it to the database so it appears on the MVD Dashboard
            try:
                save_dangerous_domain(
                    db=db,
                    domain=domain,
                    source="OSINT_OpenPhish",
                    risk_level="CRITICAL",
                    forensics_data=forensics_data
                )
                processed_count += 1
                # Small delay to not spam the IP geolocation API
                time.sleep(2.0)
            except Exception as e:
                print(f"OSINT Scanner: Failed to save domain {domain} - {e}")
                
        if processed_count > 0:
            print(f"OSINT Scanner: Successfully added {processed_count} new domains to MVD Dashboard.")
        
    finally:
        db.close()


def _scanner_loop():
    """Main background loop."""
    print("🤖 OSINT Scanner background worker started. Auto-fetching threats...")
    
    # Wait a bit after server startup before running the first scan
    _stop_event.wait(30)
    
    while not _stop_event.is_set():
        try:
            print("OSINT Scanner: Running scheduled OSINT threat sync...")
            domains = get_openphish_list()
            if domains:
                process_threats(domains)
        except Exception as e:
            print(f"OSINT Scanner loop error: {e}")
            
        # Wait for the next interval, or until stopped
        _stop_event.wait(SCAN_INTERVAL_SECONDS)
        
    print("OSINT Scanner worker stopped.")


def start_osint_scanner():
    """Starts the background OSINT scanner thread."""
    global _scanner_thread
    if _scanner_thread is None or not _scanner_thread.is_alive():
        _stop_event.clear()
        _scanner_thread = threading.Thread(target=_scanner_loop, daemon=True, name="OSINTScanner")
        _scanner_thread.start()

def stop_osint_scanner():
    """Stops the background OSINT scanner thread."""
    if _scanner_thread is not None and _scanner_thread.is_alive():
        _stop_event.set()
