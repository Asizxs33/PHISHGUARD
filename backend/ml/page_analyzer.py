"""
PhishGuard AI — Page Content Analyzer
Fetches and analyzes the actual HTML content of a given URL.
Checks for casino/gambling, phishing keywords, and suspicious forms.
"""

import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Any
import re

from urllib.parse import urlparse, urljoin
from .heuristic_analyzer import BRAND_DOMAINS

# Time to wait for a website to respond
REQUEST_TIMEOUT = 5.0

# User-Agent to avoid being immediately blocked by basic bot protection
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
}

CASINO_KEYWORDS = [
    r'\bказино\b', r'\bрулетка\b', r'\bигровые автоматы\b', r'\bvulkan\b', r'\bвулкан\b',
    r'\b1xbet\b', r'\bmelbet\b', r'\bolimpbet\b', r'\bfonbet\b', r'\bparimatch\b',
    r'\bставк[аи]\b', r'\bbetting\b', r'\bslots?\b', r'\bjackpot\b', r'\bджекпот\b',
    r'\bфриспин\b', r'\bfreespins?\b', r'\bазартные игры\b', r'\bpin-?up\b', r'\b1win\b',
    r'\bazino\b', r'\bjoycasino\b', r'\bслоты\b', r'\bлотерея\b', r'\blottery\b',
    r'\bпокер\b', r'\bpoker\b', r'\bблэкджек\b', r'\bиграть на деньги\b'
]

PHISHING_KEYWORDS = [
    r'\bвведите пароль\b', r'\bподтвердите аккаунт\b', r'\bваша карта заблокирована\b',
    r'\bverify identity\b', r'\bsecure login\b', r'\bupdate your account\b',
    r'\bсброс пароля\b', r'\bвход в интернет-банк\b', r'\bвойти в аккаунт\b',
    r'\bвведите данные карты\b', r'\bcvv\b', r'\bпин-код\b', r'\bpin code\b',
    r'\bsocial security number\b', r'\bобновить данные\b', r'\bштраф оплатить\b'
]


# Global cache for OSINT feeds
_OSINT_CACHE = []
_OSINT_LAST_FETCH = 0

def get_openphish_list() -> List[str]:
    """Fetches the latest openphish public feed and caches it for 1 hour."""
    global _OSINT_CACHE, _OSINT_LAST_FETCH
    import time
    
    current_time = time.time()
    # Cache for 1 hour (3600 seconds)
    if _OSINT_CACHE and (current_time - _OSINT_LAST_FETCH < 3600):
        return _OSINT_CACHE
        
    try:
        resp = requests.get('https://openphish.com/feed.txt', timeout=3.0)
        if resp.status_code == 200:
            _OSINT_CACHE = [line.strip() for line in resp.text.split('\n') if line.strip()]
            _OSINT_LAST_FETCH = current_time
            print(f"OSINT: Fetched {len(_OSINT_CACHE)} domains from OpenPhish.")
            return _OSINT_CACHE
    except Exception as e:
        print(f"OSINT: Failed to fetch OpenPhish: {e}")
        
    return _OSINT_CACHE


def check_domain_osint(url: str) -> List[Dict[str, Any]]:
    """Checks the URL against public OSINT feeds (OpenPhish)."""
    issues = []
    try:
        phish_list = get_openphish_list()
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Check if the domain or exact URL is in the OpenPhish database
        if any(domain in p_url for p_url in phish_list) or url in phish_list:
            issues.append({
                'type': 'osint_blacklist',
                'severity': 1.0, # 100% Critical - It is a confirmed phishing site
                'detail': f'CRITICAL: Domain {domain} is listed in public OSINT phishing databases (OpenPhish)!',
            })
    except Exception as e:
         print(f"OSINT Check error: {e}")
         
    return issues


def analyze_page_content(url: str, provided_html: str = None) -> List[Dict[str, Any]]:
    """
    Fetches the URL and analyzes its content, OR analyzes the provided HTML directly.
    Returns a list of issues found, similar to heuristic analyzer.
    """
    issues = []
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # First, do an immediate OSINT check before even downloading HTML
    osint_issues = check_domain_osint(url)
    if osint_issues:
        issues.extend(osint_issues)

    if provided_html:
        html_content = provided_html
    else:
        try:
            response = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, verify=False)
            response.raise_for_status()
            
            # FIX: Some phishing/casino sites (like sultan.egull.golf) do not send proper charset headers.
            # requests defaults to ISO-8859-1 which corrupts Cyrillic characters.
            # We force UTF-8 if the apparent encoding is different, or fallback to apparent.
            if response.encoding and response.encoding.lower() == 'iso-8859-1':
                response.encoding = response.apparent_encoding or 'utf-8'
                
            html_content = response.text
        except Exception as e:
            # We fail silently if we can't reach the page (maybe offline, maybe bot protection)
            print(f"Content Analyzer: Could not fetch {url}: {e}")
            return issues
        
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Extract visible text
    # Remove script and style elements
    for script in soup(["script", "style"]):
        script.decompose()
        
    text = soup.get_text(separator=' ', strip=True).lower()
    
    # Check title and meta description as well because sometimes content is hidden in JS
    title = soup.title.string.lower() if soup.title and soup.title.string else ""
    meta_desc = ""
    meta_tag = soup.find('meta', attrs={'name': 'description'})
    if meta_tag and 'content' in meta_tag.attrs:
        meta_desc = meta_tag['content'].lower()
        
    full_text_to_search = f"{title} {meta_desc} {text}"
    
    # 1. Search for Casino/Gambling Keywords
    found_casino = []
    for pattern in CASINO_KEYWORDS:
        if re.search(pattern, full_text_to_search):
            found_casino.append(pattern.replace(r'\b', ''))
            
    if len(found_casino) >= 2:
        issues.append({
            'type': 'casino_content',
            'severity': 0.95,
            'detail': f'Page contains gambling/casino keywords: {", ".join(found_casino[:3])}',
        })
    elif len(found_casino) == 1:
        issues.append({
            'type': 'casino_content',
            'severity': 0.60,
            'detail': f'Page contains gambling/casino keyword: {found_casino[0]}',
        })
        
    # 2. Search for Phishing Keywords (urgent action, login requests on non-official domains)
    found_phishing = []
    for pattern in PHISHING_KEYWORDS:
        if re.search(pattern, full_text_to_search):
            found_phishing.append(pattern.replace(r'\b', ''))
            
    if len(found_phishing) >= 2:
        issues.append({
            'type': 'phishing_content',
            'severity': 0.90,
            'detail': f'Page contains suspicious phishing requests (login/verification): {", ".join(found_phishing[:3])}',
        })
    elif len(found_phishing) == 1:
         issues.append({
            'type': 'phishing_content',
            'severity': 0.50,
            'detail': f'Page asks for sensitive info or login: {found_phishing[0]}',
        })
        
        
    # 3. Deep Analysis: External Forms
    # Check if a form (especially ones with password/credit card fields) submits to a DIFFERENT domain
    parsed_main_url = urlparse(url)
    main_domain = parsed_main_url.netloc.lower()
    
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action', '')
        if action and action.startswith('http'):
            parsed_action = urlparse(action)
            action_domain = parsed_action.netloc.lower()
            if main_domain and action_domain and main_domain not in action_domain and action_domain not in main_domain:
                # External form submission!
                issues.append({
                    'type': 'external_form_action',
                    'severity': 0.85,
                    'detail': f'Form submits data to a different external domain: {action_domain}',
                })
                
    # 4. Form Analysis: Suspicious CC Inputs
    cc_keywords = ['cc', 'cvv', 'card_number', 'credit_card', 'pin']
    cc_inputs_found = False
    for inp in soup.find_all('input'):
        name = inp.get('name', '').lower()
        if any(kw in name for kw in cc_keywords):
            cc_inputs_found = True
            break
            
    if cc_inputs_found:
        issues.append({
            'type': 'credit_card_form_detected',
            'severity': 0.70,
            'detail': 'Page contains inputs asking for Credit Card details or CVV.',
        })

    password_inputs = soup.find_all('input', type='password')
    if password_inputs:
        issues.append({
            'type': 'password_form_detected',
            'severity': 0.40,
            'detail': 'Page contains a password entry form.',
        })

    # 5. Deep Analysis: Dead Links (href="#")
    links = soup.find_all('a')
    total_links = len(links)
    if total_links > 5:
        dead_links = [l for l in links if l.get('href', '') in ['#', 'javascript:void(0)', '', 'javascript:;']]
        dead_ratio = len(dead_links) / total_links
        if dead_ratio > 0.4:
            issues.append({
                'type': 'high_dead_link_ratio',
                'severity': 0.65,
                'detail': f'{int(dead_ratio*100)}% of links are dead. Phishing sites often copy UI but leave links empty.',
            })

    # 6. Deep Analysis: Hidden Elements
    # Scammers hide text to bypass AV scanners (e.g. style="display:none; color:transparent;")
    hidden_elements = soup.find_all(style=re.compile(r'display:\s*none', re.I))
    if len(hidden_elements) > 3:
        # Check if they contain brand names or phishing keywords
        hidden_text = " ".join([el.get_text() for el in hidden_elements]).lower()
        for kw in PHISHING_KEYWORDS + ['kaspi', 'halyk', 'bank']:
            if re.search(kw, hidden_text):
                issues.append({
                    'type': 'hidden_suspicious_content',
                    'severity': 0.90,
                    'detail': 'Page deliberately hides phishing keywords or brand names using CSS.',
                })
                break
                
    # 7. Deep Analysis: Right-click disable
    body = soup.find('body')
    if body and ('oncontextmenu' in body.attrs or 'ondragstart' in body.attrs or 'onselectstart' in body.attrs):
        val = body.get('oncontextmenu', '').lower()
        if 'return false' in val or 'preventdefault' in val:
            issues.append({
                'type': 'right_click_disabled',
                'severity': 0.50,
                'detail': 'Page disables right-click or text selection. This is often used to prevent code inspection.',
            })

    # 8. Deep Analysis: IFrames from other domains (Loading malicious content inside Safe domain)
    iframes = soup.find_all('iframe')
    for iframe in iframes:
        src = iframe.get('src', '')
        if src.startswith('http'):
            parsed_src = urlparse(src)
            src_domain = parsed_src.netloc.lower()
            
            # Check if it's full screen (width/height 100%)
            style = iframe.get('style', '').lower()
            width = iframe.get('width', '')
            height = iframe.get('height', '')
            is_large = ('100%' in style) or (width == '100%') or (height == '100%')
            
            # Allow common trusted iframes like youtube, maps
            trusted_iframes = ['youtube.com', 'google.com/maps', 'vimeo.com', 'recaptcha']
            is_trusted = any(t in src_domain for t in trusted_iframes)
            
            if is_large and src_domain and not is_trusted and main_domain not in src_domain:
                issues.append({
                    'type': 'suspicious_iframe',
                    'severity': 0.85,
                    'detail': f'Page loads a large external <iframe> from {src_domain}. This may hide malicious content.',
                })
                
    # 9. Deep Analysis: Auto-Redirects
    
    # Check if domain belongs to a trusted brand to avoid false positives on complex web apps (like Google Search)
    is_trusted_brand = False
    for brand, official_domains in BRAND_DOMAINS.items():
        if main_domain in official_domains or any(main_domain.endswith('.' + d) for d in official_domains):
            is_trusted_brand = True
            break
            
    if not is_trusted_brand:
        # Meta refresh
        meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile(r'^refresh$', re.I)})
        if meta_refresh:
            content = meta_refresh.get('content', '')
            if 'url=' in content.lower():
                issues.append({
                    'type': 'meta_refresh_redirect',
                    'severity': 0.75,
                    'detail': 'Page contains a meta-refresh tag to auto-redirect the user to another page.',
                })
                
        # JS redirect simple check (window.location)
        # We already extracted raw text, but need raw html to search for scripts
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                script_text = script.string.lower()
                if 'window.location.replace' in script_text or 'window.location.href' in script_text:
                    if 'http' in script_text:
                        issues.append({
                            'type': 'javascript_redirect',
                            'severity': 0.40, # Lowered from 0.60 to avoid huge false positives
                            'detail': 'Page contains JavaScript that forces a redirect.',
                        })
                        break

    return issues
