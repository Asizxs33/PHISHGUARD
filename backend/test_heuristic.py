"""Quick test of the PhishGuard heuristic analyzer."""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from ml.heuristic_analyzer import analyze_url_heuristic

test_urls = [
    "https://google.com",
    "https://kaspi.kz",
    "http://kaspi-secure-login.tk/verify",
    "http://gooogle.com/login",
    "http://paypal-update.ml/confirm",
    "http://192.168.1.50/bank-login",
    "http://faceb00k.com/signin",
    "http://halykbank.account-verify.ml/login",
    "http://www.kaspi.kz@evil-redirect.tk/verify",
    "https://github.com/project",
]

for url in test_urls:
    score, verdict, details = analyze_url_heuristic(url)
    issues = details.get('issues', [])
    icon = "✅" if verdict == "safe" else "⚠️" if verdict == "suspicious" else "🚨"
    print(f"{icon} [{verdict:>10}] Score={score:.2f} | Issues={len(issues):2d} | {url}")
    for issue in issues[:3]:
        print(f"     -> [{issue['severity']:.2f}] {issue['type']}: {issue['detail'][:80]}")
    print()
