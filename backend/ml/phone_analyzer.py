"""
CyberQalqan AI — Phone Number Analyzer
Simple heuristic engine to detect scammer and high-risk phone numbers.
"""

import re
import os
import logging
import numpy as np
from typing import Dict, Any, Tuple

from ml.classifier import PhishingClassifier
from ml.features import extract_phone_features

logger = logging.getLogger(__name__)

# Try to load the Deep Learning Model
phone_classifier = None
try:
    phone_classifier = PhishingClassifier()
    phone_classifier.load('phone_model')
    logger.info("📱 Phone Deep Learning model loaded successfully.")
except Exception as e:
    logger.warning(f"⚠️ Could not load Phone Deep Learning model, falling back to pure heuristics: {e}")
    phone_classifier = None

# Known high risk country prefixes (often used in scams)
HIGH_RISK_PREFIXES = {
    '+234': 'Nigeria',
    '+91': 'India',
    '+44': 'UK (often virtual)',
    '+371': 'Latvia (often virtual)',
    '+372': 'Estonia (often virtual)',
    '+380': 'Ukraine',
}

def clean_phone_number(phone: str) -> str:
    """Remove spaces, dashes, brackets from phone number."""
    return re.sub(r'[\s\-\(\)]', '', phone)

def analyze_phone(phone: str) -> Tuple[float, str, Dict[str, Any]]:
    """
    Analyze phone number for risk.
    Returns: score, verdict, details
    """
    cleaned = clean_phone_number(phone)
    
    # Check if we have at least getting digits
    digits = re.sub(r'\D', '', cleaned)
    if not digits:
        return 0.0, "safe", {"error": "No digits found"}

    # Add + if it starts with digit
    if not cleaned.startswith('+') and digits.startswith('7'):
        cleaned = '+' + cleaned
    elif not cleaned.startswith('+') and digits.startswith('8'):
        cleaned = '+7' + digits[1:]
    elif not cleaned.startswith('+'):
        cleaned = '+' + cleaned
        
    score = 0.1
    issues = []
    
    # 1. Check length
    if len(digits) < 10 or len(digits) > 15:
        issues.append({
            'type': 'invalid_length',
            'severity': 0.8,
            'detail': f'Phone number length ({len(digits)}) is unusual.'
        })
        score += 0.5

    # 2. Check High Risk Prefixes
    found_prefix = False
    for prefix, country in HIGH_RISK_PREFIXES.items():
        if cleaned.startswith(prefix):
            issues.append({
                'type': 'high_risk_country',
                'severity': 0.7,
                'detail': f'Country code {prefix} ({country}) has a high incidence of scam calls.'
            })
            score += 0.6
            found_prefix = True
            break
            
    # 3. Check KZ/RU standard
    is_cis = cleaned.startswith('+7') or cleaned.startswith('+996') or cleaned.startswith('+998')
    if not is_cis and not found_prefix:
        issues.append({
            'type': 'foreign_number',
            'severity': 0.4,
            'detail': 'Number is from outside the standard CIS region. Be cautious if they claim to be local.'
        })
        score += 0.3
        
    # 4. Toll-free numbers used for outgoing calls (usually banks don't call FROM 8800)
    if cleaned.startswith('+7800') or cleaned.startswith('+7495') or cleaned.startswith('+7499'):
        issues.append({
            'type': 'spoofed_bank_number',
            'severity': 0.5,
            'detail': 'Banks typically do not make outgoing calls from 8-800 or 8-495 numbers. This could be spoofed.'
        })
        score += 0.4

    # ─── Neural Network Prediction ───
    ml_score = 0.0
    if phone_classifier:
        try:
            features_dict = extract_phone_features(phone)
            # Create feature vector in the order expected by the model
            feature_vector = np.array([features_dict.get(name, 0) for name in phone_classifier.feature_names])
            
            ml_score, _, ml_details = phone_classifier.predict(feature_vector)
            
            # Combine scores: ML model has high weight, but severe heuristics (like fake bank numbers) can override it
            final_score = max(score, ml_score)
            details['ml_score'] = round(ml_score, 4)
            details['ml_features_importance'] = ml_details.get('top_features', [])
            
        except Exception as e:
            logger.error(f"Error during phone ML prediction: {e}")
            final_score = score
    else:
        final_score = score

    # Cap score
    final_score = min(1.0, final_score)
    
    # Verdict
    if final_score < 0.3:
        verdict = "safe"
    elif final_score < 0.65:
        verdict = "suspicious"
    else:
        verdict = "phishing"  # mapping to high risk / scam
        
    details.update({
        'cleaned_number': cleaned,
        'issues': issues,
        'total_issues': len(issues),
        'heuristic_score': round(score, 4),
        'final_score': round(final_score, 4)
    })
    
    return round(final_score, 4), verdict, details
