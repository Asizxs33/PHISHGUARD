"""
PhishGuard AI — Heuristic Phishing Analyzer
Rule-based + heuristic phishing detection engine.
Works alongside the ML model to catch obvious phishing URLs that
the neural network might miss due to training data limitations.

NO API keys required — all logic is embedded in code.
"""

import re
import math
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, Any, List, Tuple


# ─── Known Legitimate Brand Domains ─────────────────────────────────────
# Maps brand names to their REAL official domains

BRAND_DOMAINS = {
    # Global tech
    'google': ['google.com', 'google.kz', 'google.ru', 'googleapis.com', 'gstatic.com'],
    'apple': ['apple.com', 'icloud.com', 'appleid.apple.com'],
    'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'microsoftonline.com'],
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'aws.amazon.com'],
    'facebook': ['facebook.com', 'fb.com', 'messenger.com', 'meta.com'],
    'instagram': ['instagram.com'],
    'twitter': ['twitter.com', 'x.com'],
    'whatsapp': ['whatsapp.com', 'web.whatsapp.com'],
    'telegram': ['telegram.org', 'web.telegram.org', 't.me'],
    'netflix': ['netflix.com'],
    'paypal': ['paypal.com', 'paypal.me'],
    'ebay': ['ebay.com'],
    'linkedin': ['linkedin.com'],
    'youtube': ['youtube.com', 'youtu.be'],
    'tiktok': ['tiktok.com'],
    'discord': ['discord.com', 'discord.gg', 'discordapp.com'],
    'zoom': ['zoom.us', 'zoom.com'],
    'spotify': ['spotify.com'],
    'github': ['github.com', 'github.io'],
    'dropbox': ['dropbox.com'],
    'reddit': ['reddit.com'],
    # Kazakhstan
    'kaspi': ['kaspi.kz', 'kaspi.com'],
    'halyk': ['halykbank.kz', 'homebank.kz'],
    'halykbank': ['halykbank.kz', 'homebank.kz'],
    'homebank': ['homebank.kz'],
    'egov': ['egov.kz'],
    'forte': ['forte.kz', 'fortebank.com'],
    'fortebank': ['forte.kz', 'fortebank.com'],
    'jusan': ['jysanbank.kz', 'jusan.kz'],
    'bereke': ['berekebank.kz'],
    'freedom': ['ffin.kz', 'freedomfinance.kz', 'freedom24.com'],
    'kolesa': ['kolesa.kz'],
    'krisha': ['krisha.kz'],
    'olx': ['olx.kz'],
    # Russia
    'sberbank': ['sberbank.ru', 'online.sberbank.ru', 'sber.ru'],
    'sber': ['sberbank.ru', 'sber.ru'],
    'tinkoff': ['tinkoff.ru', 'tinkoff.com'],
    'vtb': ['vtb.ru'],
    'yandex': ['yandex.ru', 'yandex.kz', 'ya.ru'],
    'mail': ['mail.ru'],
    'vk': ['vk.com', 'vk.ru'],
    'ozon': ['ozon.ru'],
    'wildberries': ['wildberries.ru', 'wb.ru'],
    'avito': ['avito.ru'],
    'canva': ['canva.com'],
    'figma': ['figma.com'],
    'trello': ['trello.com'],
    'notion': ['notion.so', 'notion.site'],
}

# ─── Suspicious TLD list (expanded) ─────────────────────────────────────

HIGHLY_SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq',  # Free domains, heavily abused
    '.xyz', '.top', '.win', '.bid', '.stream', '.racing',
    '.download', '.loan', '.date', '.faith', '.review',
    '.science', '.party', '.click', '.link', '.work', '.buzz',
    '.rest', '.monster', '.surf', '.icu', '.cam', '.quest',
    '.cfd', '.sbs', '.autos', '.boats',
]

# ─── Homograph / Confusable characters ──────────────────────────────────
# Characters that look like Latin letters but are from other alphabets (IDN homograph attack)

HOMOGRAPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',
    'х': 'x', 'і': 'i', 'ј': 'j', 'ɡ': 'g', 'ɑ': 'a',
    'ᴏ': 'o', 'ⅰ': 'i', 'ℓ': 'l', 'ν': 'v', 'τ': 't',
    '0': 'o', '1': 'l', '!': 'i',
}

# Common letter substitutions in typosquatting
TYPO_SUBSTITUTIONS = {
    'l': ['1', 'i', '|'],
    'o': ['0', 'ο'],  # Latin o -> zero, Greek omicron
    'i': ['1', 'l', '!', 'í'],
    'a': ['@', 'а', 'ä'],  # Latin a -> at sign, Cyrillic a
    'e': ['3', 'е', 'ë'],  # Latin e -> 3, Cyrillic e
    's': ['5', '$'],
    'g': ['9', 'q'],
    'b': ['d', '6'],
    't': ['7', '+'],
    'm': ['n', 'rn'],  # rn looks like m
}

# ─── Casino & Gambling Keywords ──────────────────────────────────────────
CASINO_KEYWORDS = [
    'casino', 'vulkan', 'vulcan', '1xbet', 'betting', 'stavki', 'azino',
    'joycasino', 'sloty', 'slots', 'spin', 'jackpot', 'pinup', '1win',
    'melbet', 'parimatch', 'olimpbet', 'fonbet', 'казино', 'вулкан',
    'ставка', 'ставки', 'рулетка', 'автоматы', 'азино', 'win', 'lotto',
    'lottery', 'лотерея', 'розыгрыш'
]


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein (edit) distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def _normalize_domain(domain: str) -> str:
    """Normalize domain for comparison (lowercase, strip www.)."""
    domain = domain.lower().strip()
    if domain.startswith('www.'):
        domain = domain[4:]
    # Remove port
    if ':' in domain:
        domain = domain.split(':')[0]
    return domain


def _extract_base_domain(domain: str) -> str:
    """Extract base domain (last 2 parts for normal TLDs, last 3 for country-code TLDs)."""
    parts = domain.split('.')
    if len(parts) <= 2:
        return domain
    # Country-code second-level domains like .co.uk, .com.kz
    country_second = ['.co.', '.com.', '.org.', '.net.', '.gov.', '.edu.']
    rejoined = '.' + '.'.join(parts[-2:])
    if any(rejoined.startswith(cs.rstrip('.')) for cs in country_second):
        return '.'.join(parts[-3:]) if len(parts) >= 3 else domain
    return '.'.join(parts[-2:])


def check_brand_impersonation(url: str, domain: str) -> List[Dict[str, Any]]:
    """
    Check if the URL is trying to impersonate a known brand.
    Returns list of detected issues.
    """
    issues = []
    domain_lower = _normalize_domain(domain)
    base_domain = _extract_base_domain(domain_lower)
    url_lower = url.lower()

    for brand, official_domains in BRAND_DOMAINS.items():
        # Skip if the domain IS the official domain
        if base_domain in official_domains or domain_lower in official_domains:
            continue

        # Check if brand name appears in the domain but it's NOT the real domain
        if brand in domain_lower:
            issues.append({
                'type': 'brand_impersonation',
                'severity': 0.9,
                'brand': brand,
                'detail': f'Domain contains "{brand}" but is not an official {brand} domain',
                'official_domains': official_domains[:3],
            })

        # Check for brand name in subdomain (e.g., kaspi.phishing.tk)
        domain_parts = domain_lower.split('.')
        if len(domain_parts) > 2:
            for part in domain_parts[:-2]:  # Check subdomains only
                if brand in part and len(brand) >= 4:
                    issues.append({
                        'type': 'brand_in_subdomain',
                        'severity': 0.85,
                        'brand': brand,
                        'detail': f'Brand "{brand}" found in subdomain — likely impersonation',
                    })

        # Check URL path for brand names (e.g., phishing.tk/kaspi/login)
        path_lower = urlparse(url_lower).path
        if brand in path_lower and len(brand) >= 4:
            if base_domain not in official_domains:
                issues.append({
                    'type': 'brand_in_path',
                    'severity': 0.7,
                    'brand': brand,
                    'detail': f'Brand "{brand}" found in URL path but domain is not official',
                })

    return issues


def check_typosquatting(domain: str) -> List[Dict[str, Any]]:
    """
    Check if the domain is a typosquat (looks similar to a known brand).
    Uses Levenshtein distance for fuzzy matching.
    Only keeps the best (closest) match per brand to avoid duplicates.
    """
    issues = []
    domain_lower = _normalize_domain(domain)
    base_domain = _extract_base_domain(domain_lower)
    domain_name = base_domain.split('.')[0]  # Just the domain name without TLD

    for brand, official_domains in BRAND_DOMAINS.items():
        if base_domain in official_domains:
            continue

        # Find the best (closest) match among all official domains for this brand
        best_match = None
        best_distance = 999

        for official in official_domains:
            official_name = official.split('.')[0]

            # Only check if domains are similar length (likely typo)
            if abs(len(domain_name) - len(official_name)) > 3:
                continue

            distance = _levenshtein_distance(domain_name, official_name)

            # Very close match (1-2 char difference) = likely typosquatting
            if 0 < distance <= 2 and len(official_name) >= 4 and distance < best_distance:
                best_distance = distance
                best_match = {
                    'type': 'typosquatting',
                    'severity': 0.95 if distance == 1 else 0.8,
                    'brand': brand,
                    'detail': f'Domain "{domain_name}" looks like "{official_name}" (typosquatting, {distance} char difference)',
                    'distance': distance,
                    'similar_to': official,
                }

        if best_match:
            issues.append(best_match)

    return issues


def check_casino_patterns(url: str, domain: str) -> List[Dict[str, Any]]:
    """
    Check if the URL or domain contains casino, gambling or betting keywords.
    """
    issues = []
    domain_lower = _normalize_domain(domain)
    url_lower = url.lower()
    
    keyword_matches = [kw for kw in CASINO_KEYWORDS if kw in url_lower]
    
    # We assign higher severity if the keyword is in the domain
    domain_matches = [kw for kw in CASINO_KEYWORDS if kw in domain_lower]
    
    if domain_matches:
        issues.append({
            'type': 'casino_gambling',
            'severity': 0.85,
            'detail': f'Domain contains gambling/casino keywords: {", ".join(domain_matches[:3])}',
        })
    elif keyword_matches:
        issues.append({
            'type': 'casino_gambling',
            'severity': 0.6,
            'detail': f'URL path contains gambling/casino keywords: {", ".join(keyword_matches[:3])}',
        })

    return issues


def check_url_patterns(url: str, domain: str, parsed) -> List[Dict[str, Any]]:
    """
    Check for suspicious URL patterns commonly used in phishing.
    """
    issues = []
    domain_lower = _normalize_domain(domain)
    path = parsed.path or ''
    url_lower = url.lower()

    # 1. IP address as domain
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, domain_lower.split(':')[0]):
        issues.append({
            'type': 'ip_address_domain',
            'severity': 0.85,
            'detail': 'URL uses an IP address instead of a domain name',
        })

    # 2. Extremely long URL (common in phishing to hide real destination)
    # Skip length check for trusted large platforms
    trusted_long_platforms = ['canva.com', 'figma.com', 'google.com', 'microsoft.com', 'sharepoint.com']
    if len(url) > 150 and not any(p in domain_lower for p in trusted_long_platforms):
        issues.append({
            'type': 'very_long_url',
            'severity': 0.4,
            'detail': f'URL is unusually long ({len(url)} chars) — may be hiding malicious content',
        })

    # 3. Multiple subdomains (e.g., login.kaspi.verify.evil.tk)
    subdomain_count = len(domain_lower.split('.')) - 2
    if subdomain_count >= 3:
        issues.append({
            'type': 'excessive_subdomains',
            'severity': 0.7,
            'detail': f'Domain has {subdomain_count} subdomains — very unusual for legitimate sites',
        })

    # 4. @ symbol in URL (can redirect to different URL)
    if '@' in url:
        issues.append({
            'type': 'at_symbol_redirect',
            'severity': 0.9,
            'detail': 'URL contains @ symbol — this can redirect to a different site than shown',
        })

    # 5. URL encoding abuse (excessive %XX sequences)
    encoded_chars = len(re.findall(r'%[0-9a-fA-F]{2}', url))
    if encoded_chars > 5:
        issues.append({
            'type': 'excessive_encoding',
            'severity': 0.6,
            'detail': f'URL has {encoded_chars} encoded characters — may be hiding malicious content',
        })

    # 6. No HTTPS
    if not url_lower.startswith('https://'):
        issues.append({
            'type': 'no_https',
            'severity': 0.5,
            'detail': 'URL does not use HTTPS encryption',
        })

    # 7. Suspicious path keywords
    phishing_path_keywords = [
        'login', 'signin', 'sign-in', 'log-in', 'verify', 'confirm',
        'update', 'secure', 'account', 'banking', 'password', 'credential',
        'authenticate', 'validate', 'authorize', 'restore', 'recover',
        'suspend', 'restrict', 'unlock', 'reactivate', 'identity',
        'webscr', 'cmd=login', 'wp-admin', 'admin/login',
    ]
    path_keyword_count = sum(1 for kw in phishing_path_keywords if kw in path.lower())
    if path_keyword_count >= 2:
        issues.append({
            'type': 'suspicious_path',
            'severity': 0.7,
            'detail': f'URL path contains {path_keyword_count} suspicious keywords (login, verify, etc.)',
        })
    elif path_keyword_count == 1:
        issues.append({
            'type': 'suspicious_path',
            'severity': 0.35,
            'detail': 'URL path contains a suspicious keyword',
        })

    # 8. Suspicious TLD
    for tld in HIGHLY_SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            issues.append({
                'type': 'suspicious_tld',
                'severity': 0.65,
                'detail': f'Domain uses suspicious TLD "{tld}" — commonly abused for phishing',
            })
            break

    # 9. Hyphens in domain (e.g., kaspi-bank-login.tk)
    domain_name = domain_lower.split('.')[0] if '.' in domain_lower else domain_lower
    hyphen_count = domain_name.count('-')
    if hyphen_count >= 2:
        issues.append({
            'type': 'excessive_hyphens',
            'severity': 0.6,
            'detail': f'Domain has {hyphen_count} hyphens — legitimate sites rarely use many hyphens',
        })

    # 10. Mixed scripts (Cyrillic + Latin = IDN homograph attack)
    has_latin = bool(re.search(r'[a-zA-Z]', domain_lower))
    has_cyrillic = bool(re.search(r'[а-яА-ЯёЁіІғҒүҮұҰқҚөӨңНäÄ]', domain))
    if has_latin and has_cyrillic:
        issues.append({
            'type': 'mixed_scripts',
            'severity': 0.95,
            'detail': 'Domain mixes Latin and Cyrillic characters — classic IDN homograph attack',
        })

    # 11. Data URI in URL
    if 'data:' in url_lower:
        issues.append({
            'type': 'data_uri',
            'severity': 0.95,
            'detail': 'URL contains a data URI — potentially hiding malicious content',
        })

    # 12. JavaScript in URL
    if 'javascript:' in url_lower:
        issues.append({
            'type': 'javascript_uri',
            'severity': 1.0,
            'detail': 'URL contains JavaScript code — definitely malicious',
        })

    # 13. Double extension trick (e.g., document.pdf.exe)
    if re.search(r'\.\w{2,4}\.\w{2,4}$', path):
        double_ext = re.search(r'\.(\w{2,4})\.(\w{2,4})$', path)
        if double_ext:
            ext1, ext2 = double_ext.groups()
            dangerous_exts = ['exe', 'bat', 'cmd', 'scr', 'js', 'vbs', 'ps1', 'msi', 'com']
            if ext2.lower() in dangerous_exts:
                issues.append({
                    'type': 'double_extension',
                    'severity': 0.95,
                    'detail': f'File has double extension (.{ext1}.{ext2}) — hiding executable as document',
                })

    # 14. URL shortener
    shorteners = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
        'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy',
        'tinycc.com', 'short.io', 'v.gd', 'clck.ru', 'qps.ru',
    ]
    if any(s in domain_lower for s in shorteners):
        issues.append({
            'type': 'url_shortener',
            'severity': 0.4,
            'detail': 'URL uses a shortener service — real destination is hidden',
        })

    # 15. Punycode domain (xn--)
    if 'xn--' in domain_lower:
        issues.append({
            'type': 'punycode_domain',
            'severity': 0.8,
            'detail': 'Domain uses Punycode (internationalized encoding) — may be a homograph attack',
        })

    # 16. Port in URL (e.g., :8080, :443 is fine)
    if ':' in domain:
        port_match = re.search(r':(\d+)$', domain)
        if port_match:
            port = int(port_match.group(1))
            if port not in [80, 443]:
                issues.append({
                    'type': 'unusual_port',
                    'severity': 0.5,
                    'detail': f'URL uses unusual port :{port} — legitimate sites use standard ports',
                })

    # 17. Redirects in URL (contain another URL inside)
    redirect_patterns = [
        r'redirect[=\?]', r'url[=\?]', r'next[=\?]', r'goto[=\?]',
        r'return[=\?]', r'dest[=\?]', r'link[=\?]', r'target[=\?]',
    ]
    for pattern in redirect_patterns:
        if re.search(pattern, url_lower):
            issues.append({
                'type': 'redirect_parameter',
                'severity': 0.6,
                'detail': 'URL contains redirect parameters — may redirect to malicious site after loading',
            })
            break

    # 18. Multiple dots in domain name part
    if domain_lower.count('.') >= 4:
        issues.append({
            'type': 'many_dots',
            'severity': 0.5,
            'detail': f'Domain has {domain_lower.count(".")} dots — unusually complex structure',
        })

    return issues


def analyze_url_heuristic(url: str) -> Tuple[float, str, Dict[str, Any]]:
    """
    Perform comprehensive heuristic analysis of a URL.
    
    Returns:
        score: float 0.0 (safe) to 1.0 (phishing)
        verdict: str "safe", "suspicious", or "phishing"
        details: dict with analysis breakdown
    """
    # Normalize URL
    if not url.startswith(('http://', 'https://', 'ftp://')):
        url_to_parse = f'http://{url}'
    else:
        url_to_parse = url

    try:
        parsed = urlparse(url_to_parse)
    except Exception:
        return 1.0, "phishing", {
            'error': 'URL could not be parsed',
            'issues': [{'type': 'unparseable', 'severity': 1.0, 'detail': 'URL is malformed'}],
        }

    domain = parsed.netloc or parsed.path.split('/')[0]
    domain = domain.lower()

    # Collect all issues
    all_issues = []

    # Run all checks
    all_issues.extend(check_brand_impersonation(url, domain))
    all_issues.extend(check_typosquatting(domain))
    all_issues.extend(check_url_patterns(url, domain, parsed))
    all_issues.extend(check_casino_patterns(url, domain))

    # Calculate final score based on issues
    if not all_issues:
        # No issues found — likely safe
        score = 0.05
    else:
        # Weighted scoring: take top 5 severity scores
        severities = sorted([issue['severity'] for issue in all_issues], reverse=True)
        top_severities = severities[:5]

        # Primary score from max severity
        max_severity = top_severities[0]

        # Bonus for multiple issues (cumulative evidence)
        issue_bonus = min(0.15, len(all_issues) * 0.03)

        # Calculate weighted average of top severities
        if len(top_severities) > 1:
            avg_severity = sum(top_severities) / len(top_severities)
            score = max_severity * 0.6 + avg_severity * 0.25 + issue_bonus
        else:
            score = max_severity * 0.85 + issue_bonus

        score = min(1.0, max(0.0, score))

    # Determine verdict
    if score < 0.3:
        verdict = "safe"
    elif score < 0.65:
        verdict = "suspicious"
    else:
        verdict = "phishing"

    # Build details
    details = {
        'heuristic_score': round(score, 4),
        'total_issues': len(all_issues),
        'issues': all_issues,
        'checks_performed': [
            'brand_impersonation',
            'typosquatting',
            'url_pattern_analysis',
            'tld_check',
            'homograph_detection',
            'url_shortener_detection',
        ],
    }

    return round(score, 4), verdict, details


def combine_scores(ml_score: float, heuristic_score: float,
                   ml_verdict: str, heuristic_verdict: str,
                   heuristic_issues: List[Dict]) -> Tuple[float, str]:
    """
    Combine ML model score with heuristic score for final verdict.
    
    Strategy:
    - If heuristic finds HIGH severity issues (brand impersonation, typosquatting),
      trust heuristic more heavily
    - If ML and heuristic agree, boost confidence
    - If they disagree, lean toward the more cautious (higher) score
    """
    # Check if there are critical heuristic findings
    critical_issues = [i for i in heuristic_issues if i.get('severity', 0) >= 0.85]
    has_critical = len(critical_issues) > 0

    if has_critical:
        # Heuristic found strong evidence — trust it more
        # (brand impersonation, typosquatting, homograph attacks)
        final_score = heuristic_score * 0.7 + ml_score * 0.3
    elif heuristic_score > 0.6 and ml_score > 0.6:
        # Both agree it's phishing — high confidence
        final_score = max(ml_score, heuristic_score) * 0.9 + min(ml_score, heuristic_score) * 0.1
    elif heuristic_score > 0.5 or ml_score > 0.5:
        # One thinks suspicious, be cautious
        final_score = max(ml_score, heuristic_score) * 0.6 + min(ml_score, heuristic_score) * 0.4
    else:
        # Both think safe
        final_score = ml_score * 0.5 + heuristic_score * 0.5

    final_score = min(1.0, max(0.0, round(final_score, 4)))

    # Determine final verdict
    if final_score < 0.3:
        verdict = "safe"
    elif final_score < 0.65:
        verdict = "suspicious"
    else:
        verdict = "phishing"

    return final_score, verdict
