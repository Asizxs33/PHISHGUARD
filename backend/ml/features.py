"""
PhishGuard AI — Feature Extraction Module
Extracts features from URLs and email content for phishing detection.
"""

import re
import math
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List

# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_URL_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'update', 'secure', 'banking',
    'confirm', 'password', 'credential', 'suspend', 'restrict', 'unlock',
    'authenticate', 'wallet', 'paypal', 'ebay', 'amazon', 'apple', 'microsoft',
    'netflix', 'facebook', 'instagram', 'whatsapp', 'telegram', 'bank',
    'security', 'alert', 'urgent', 'immediate', 'expired', 'blocked',
    'recover', 'restore', 'validate', 'authorize', 'click-here', 'free',
    'prize', 'winner', 'gift', 'reward', 'bonus', 'offer', 'limited',
]

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.win', '.bid',
    '.stream', '.racing', '.download', '.loan', '.date', '.faith',
    '.review', '.science', '.party', '.click', '.link', '.work', '.buzz',
]

# Urgency keywords in emails (multilingual: EN/RU/KZ)
URGENCY_KEYWORDS = {
    'en': ['urgent', 'immediately', 'action required', 'verify now', 'suspended',
           'unauthorized', 'click here', 'confirm identity', 'limited time',
           'act now', 'don\'t ignore', 'your account', 'has been compromised',
           'expire', 'deactivate', 'within 24 hours', 'security alert'],
    'ru': ['срочно', 'немедленно', 'подтвердите', 'ваш аккаунт', 'заблокирован',
           'нажмите здесь', 'безопасность', 'пароль', 'верификация',
           'действуйте сейчас', 'ограниченное время', 'ваш счёт',
           'несанкционированный', 'подозрительная активность', 'в течение 24 часов'],
    'kz': ['шұғыл', 'дереу', 'растаңыз', 'сіздің аккаунт', 'бұғатталды',
           'мұнда басыңыз', 'қауіпсіздік', 'құпиясөз', 'тексеру',
           'қазір әрекет етіңіз', 'шектеулі уақыт', 'сіздің шот'],
}


def extract_url_features(url: str) -> Dict[str, Any]:
    """Extract numerical features from a URL for ML classification."""
    features = {}

    try:
        parsed = urlparse(url if '://' in url else f'http://{url}')
    except Exception:
        parsed = urlparse(f'http://{url}')

    domain = parsed.netloc or parsed.path.split('/')[0]
    path = parsed.path or ''
    query = parsed.query or ''

    # 1. URL length
    features['url_length'] = len(url)

    # 2. Has IP address instead of domain
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    features['has_ip'] = 1 if re.match(ip_pattern, domain.split(':')[0]) else 0

    # 3. Number of dots in URL
    features['num_dots'] = url.count('.')

    # 4. HTTPS presence
    features['has_https'] = 1 if url.lower().startswith('https') else 0

    # 5. Number of subdomains
    domain_parts = domain.split(':')[0].split('.')
    features['num_subdomains'] = max(0, len(domain_parts) - 2)

    # 6. Suspicious keywords count
    url_lower = url.lower()
    features['suspicious_keywords'] = sum(1 for kw in SUSPICIOUS_URL_KEYWORDS if kw in url_lower)

    # 7. Special character ratio
    special_chars = sum(1 for c in url if c in '@!#$%^&*()_+-=[]{}|;:,<>?~`')
    features['special_char_ratio'] = special_chars / max(len(url), 1)

    # 8. Path depth
    features['path_depth'] = len([p for p in path.split('/') if p])

    # 9. Query parameter count
    features['query_params'] = len(parse_qs(query))

    # 10. Domain length
    features['domain_length'] = len(domain)

    # 11. Has @ symbol (common in phishing)
    features['has_at_symbol'] = 1 if '@' in url else 0

    # 12. Has double slash in path
    features['has_double_slash'] = 1 if '//' in path else 0

    # 13. Has suspicious TLD
    features['suspicious_tld'] = 1 if any(domain.lower().endswith(tld) for tld in SUSPICIOUS_TLDS) else 0

    # 14. URL entropy (randomness)
    features['url_entropy'] = _calculate_entropy(url)

    # 15. Digit ratio in domain
    digits = sum(1 for c in domain if c.isdigit())
    features['digit_ratio'] = digits / max(len(domain), 1)

    # 16. Hyphen count in domain
    features['hyphen_count'] = domain.count('-')

    # 17. Has port number
    features['has_port'] = 1 if ':' in domain and not domain.startswith('[') else 0

    # 18. URL shortener detection
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly']
    features['is_shortened'] = 1 if any(s in domain.lower() for s in shorteners) else 0

    return features


def extract_email_features(subject: str = '', body: str = '', sender: str = '') -> Dict[str, Any]:
    """Extract features from email content for phishing detection."""
    features = {}
    text = f"{subject} {body}".lower()

    # 1. Subject length
    features['subject_length'] = len(subject)

    # 2. Body length
    features['body_length'] = len(body)

    # 3. Urgency score (multilingual)
    urgency = 0
    for lang_keywords in URGENCY_KEYWORDS.values():
        urgency += sum(1 for kw in lang_keywords if kw.lower() in text)
    features['urgency_score'] = urgency

    # 4. Link count in body
    link_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+' 
    links = re.findall(link_pattern, body)
    features['link_count'] = len(links)

    # 5. Sender domain analysis
    sender_domain = sender.split('@')[-1] if '@' in sender else ''
    features['sender_domain_length'] = len(sender_domain)

    # 6. Free email provider
    free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'mail.ru', 'yandex.ru']
    features['free_email_provider'] = 1 if sender_domain.lower() in free_providers else 0

    # 7. Suspicious sender (mismatch indicators)
    features['sender_has_numbers'] = sum(1 for c in sender.split('@')[0] if c.isdigit()) if '@' in sender else 0

    # 8. HTML tag presence
    html_tags = len(re.findall(r'<[^>]+>', body))
    features['html_tag_count'] = html_tags

    # 9. HTML to text ratio
    clean_text = re.sub(r'<[^>]+>', '', body)
    features['html_text_ratio'] = html_tags / max(len(clean_text.split()), 1)

    # 10. Exclamation marks count
    features['exclamation_count'] = text.count('!')

    # 11. Question marks count
    features['question_count'] = text.count('?')

    # 12. ALL CAPS words ratio
    words = body.split()
    caps_words = sum(1 for w in words if w.isupper() and len(w) > 2)
    features['caps_ratio'] = caps_words / max(len(words), 1)

    # 13. Contains attachment mention
    attachment_words = ['attachment', 'attached', 'вложение', 'прикреплен', 'тіркеме', 'тіркелген']
    features['mentions_attachment'] = 1 if any(w in text for w in attachment_words) else 0

    # 14. Contains money/currency references
    money_pattern = r'[\$€₽₸]\s*\d+|\d+\s*(?:dollar|euro|рубл|тенге|USD|EUR|KZT)'
    features['has_money_ref'] = 1 if re.search(money_pattern, text, re.IGNORECASE) else 0

    # 15. Spelling/grammar indicators (simplified)
    features['text_entropy'] = _calculate_entropy(text)

    # If there are links in the body, analyze the first one
    if links:
        url_feats = extract_url_features(links[0])
        features['first_link_suspicious'] = url_feats.get('suspicious_keywords', 0)
        features['first_link_has_ip'] = url_feats.get('has_ip', 0)
    else:
        features['first_link_suspicious'] = 0
        features['first_link_has_ip'] = 0

    return features


def _calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 4)


def get_url_feature_names() -> List[str]:
    """Return ordered list of URL feature names."""
    return [
        'url_length', 'has_ip', 'num_dots', 'has_https', 'num_subdomains',
        'suspicious_keywords', 'special_char_ratio', 'path_depth', 'query_params',
        'domain_length', 'has_at_symbol', 'has_double_slash', 'suspicious_tld',
        'url_entropy', 'digit_ratio', 'hyphen_count', 'has_port', 'is_shortened'
    ]


def get_email_feature_names() -> List[str]:
    """Return ordered list of email feature names."""
    return [
        'subject_length', 'body_length', 'urgency_score', 'link_count',
        'sender_domain_length', 'free_email_provider', 'sender_has_numbers',
        'html_tag_count', 'html_text_ratio', 'exclamation_count', 'question_count',
        'caps_ratio', 'mentions_attachment', 'has_money_ref', 'text_entropy',
        'first_link_suspicious', 'first_link_has_ip'
    ]
