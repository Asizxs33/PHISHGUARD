import os
import sys

# ensure we can import from backend
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'backend'))
sys.path.insert(0, backend_dir)

from ml.heuristic_analyzer import analyze_url_heuristic
from ml.phone_analyzer import analyze_phone

def run_tests():
    print("--- URL Heuristics (Casino) ---")
    casino_urls = ["http://vulkan-casino.com", "https://1xbet.kz/login", "https://safe-blog.com/about"]
    for url in casino_urls:
        score, verdict, details = analyze_url_heuristic(url)
        print(f"URL: {url}")
        print(f"Score: {score}, Verdict: {verdict}")
        if details.get('issues'):
             print(f"Issues: {[issue['type'] for issue in details['issues']]}")
        print()

    print("--- Phone Analysis ---")
    phones = [
         "+7 701 555 1234", 
         "+234 809 333 4444", 
         "8 800 555 3535", 
         "+7 999 xyz", 
         "87015555555", 
         "+44 7904 010373",
         "8-495-123-45-67"
    ]
    for phone in phones:
        score, verdict, details = analyze_phone(phone)
        print(f"Phone: {phone}")
        print(f"Score: {score}, Verdict: {verdict}")
        if details.get('issues'):
             print(f"Issues: {[issue['type'] for issue in details['issues']]}")
        print()

if __name__ == '__main__':
    run_tests()
