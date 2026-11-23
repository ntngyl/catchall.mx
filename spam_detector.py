#!/usr/bin/env python3
"""
Spam, phishing, and abuse detection for CatchAll.mx
"""

import re
import dkim
import dns.resolver

SPAM_PATTERNS = [
    r'\b(viagra|cialis|casino|crypto|bitcoin|lottery|prize|winner)\b',
    r'click\s+(here|now|below)',
    r'urgent.*(transfer|payment|action)',
    r'nigerian\s+prince',
    r'you\s+have\s+won',
    r'act\s+now',
    r'limited\s+time',
    r'earn\s+money\s+fast',
]

PHISHING_PATTERNS = [
    r'service\s+suspension',
    r'invoice.*ready',
    r'account.*(suspended|locked|disabled|compromised)',
    r'payment.*(overdue|required|pending)',
    r'sharepoint.*document',
    r'verify.*(immediately|now|account)',
    r'urgent.*action.*required',
    r'security\s+alert.*account',
    r'password\s+expir',
    r'unusual\s+activity.*detected',
    r'sign\s+in.*(attempt|from|detected)',
    r'delivery\s+failed.*(click|open|view)',
    r'your\s+access\s+has\s+been\s+(revoked|suspended)',
    r'update\s+your\s+payment\s+method',
    r'\d{4,}[- ]\d{4,}[- ]\d{4,}',  # Fake invoice/reference numbers
]

DISPOSABLE_SENDER_PATTERNS = [
    r'@\d+[a-f]{10,}\.',
    r'@.*\.(tk|ml|ga|cf|gq)',
    r'@.*\d{8,}.*\.com$',
]

SUSPICIOUS_EXTENSIONS = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.vbs', '.js', '.zip', '.rar']


def extract_sender(email_content):
    """Extract the envelope/display sender from email headers."""
    match = re.search(r'(?i)^From:\s*(.+)$', email_content, re.MULTILINE)
    if match:
        return match.group(1).strip()
    match = re.search(r'(?i)^Return-Path:\s*<([^>]+)>', email_content, re.MULTILINE)
    if match:
        return match.group(1).strip()
    return ''


def check_spf(domain, ip):
    """
    Basic SPF check for a domain + IP.
    Returns: (pass_soft: bool, reason: str)
    """
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('v=spf1'):
                if '-all' in txt:
                    return False, "SPF hard fail (-all)"
                elif '~all' in txt:
                    return False, "SPF soft fail (~all)"
        return True, "No SPF or permissive"
    except Exception as e:
        return True, f"SPF lookup error: {e}"


def check_dkim_validity(email_content):
    """
    Check if DKIM signature is present and valid.
    Returns: (valid: bool, reason: str)
    """
    if b'DKIM-Signature' not in (
        email_content.encode() if isinstance(email_content, str) else email_content
    ):
        return True, "No DKIM signature"

    try:
        email_bytes = (
            email_content.encode() if isinstance(email_content, str) else email_content
        )
        valid = dkim.verify(email_bytes)
        if valid:
            return True, "DKIM valid"
        return False, "DKIM signature invalid"
    except Exception as e:
        return False, f"DKIM verify error: {e}"


def calculate_spam_score(email_content, subject=''):
    """
    Calculate spam/phishing score based on content.
    Returns: integer score (0-100+)
    """
    score = 0
    content_lower = email_content.lower()
    subject_lower = subject.lower()

    # Classic spam pattern matching
    for pattern in SPAM_PATTERNS:
        if re.search(pattern, content_lower):
            score += 25

    # Phishing pattern matching
    for pattern in PHISHING_PATTERNS:
        if re.search(pattern, content_lower):
            score += 40
        if re.search(pattern, subject_lower):
            score += 40

    # URL count
    urls = re.findall(r'https?://', email_content)
    url_count = len(urls)
    if url_count > 5:
        score += 20
    if url_count > 10:
        score += 30

    # All caps subject
    if subject and len(subject) > 10 and subject.isupper():
        score += 15

    # Suspicious extensions
    for ext in SUSPICIOUS_EXTENSIONS:
        if ext in content_lower:
            score += 30
            break

    # Image-only emails with links
    text_content = re.sub(r'<[^>]+>', '', email_content)
    if len(text_content.strip()) < 50 and url_count > 0:
        score += 20

    # Disposable/throwaway sender domains
    sender = extract_sender(email_content)
    for pattern in DISPOSABLE_SENDER_PATTERNS:
        if re.search(pattern, sender.lower()):
            score += 30

    # Spoofed display name (From: Real Company <attacker@evil.com>)
    from_match = re.search(r'From:\s*([^<]+)\s*<([^>]+)>', email_content, re.IGNORECASE)
    if from_match:
        display_name = from_match.group(1).strip()
        actual_email = from_match.group(2).strip()
        # If display name looks like an email domain but doesn't match actual sender domain
        if '@' in display_name:
            display_domain = display_name.split('@')[-1].strip()
            actual_domain = actual_email.split('@')[-1].strip()
            if display_domain and actual_domain and display_domain != actual_domain:
                if '.' in display_domain:
                    score += 35  # Display name spoofing

    # Excessive redirects in URLs
    redirects = re.findall(r'https?://[^/\s]+[^\s]*redirect', content_lower)
    if len(redirects) > 2:
        score += 25

    return score


def should_block_spam(email_content, subject='', spam_level='moderate'):
    """
    Determine if email should be blocked.
    spam_level: 'strict' (>35), 'moderate' (>50), 'off' (never block)
    """
    if spam_level == 'off':
        return False

    score = calculate_spam_score(email_content, subject)

    if spam_level == 'strict':
        return score > 35
    elif spam_level == 'moderate':
        return score > 50

    return False


def should_quarantine(email_content, subject='', spam_level='moderate'):
    """
    Determine if email should be quarantined (held for review).
    Quarantine threshold is lower than block.
    Returns: (should_quarantine: bool, score: int)
    """
    if spam_level == 'off':
        return False, 0

    score = calculate_spam_score(email_content, subject)

    if spam_level == 'strict':
        return score > 20, score
    elif spam_level == 'moderate':
        return score > 35, score

    return False, score


def validate_sender_authenticity(email_content, connecting_ip=None):
    """
    Run SPF + DKIM checks on the sender.
    Returns: dict with pass/fail details.
    """
    sender = extract_sender(email_content)
    sender_domain = sender.split('@')[-1].strip('>') if '@' in sender else ''

    result = {
        'spf_pass': True,
        'spf_reason': 'No sender domain',
        'dkim_pass': True,
        'dkim_reason': 'No DKIM',
        'overall_pass': True,
    }

    if sender_domain:
        spf_ok, spf_reason = check_spf(sender_domain, connecting_ip or '127.0.0.1')
        result['spf_pass'] = spf_ok
        result['spf_reason'] = spf_reason

    dkim_ok, dkim_reason = check_dkim_validity(email_content)
    result['dkim_pass'] = dkim_ok
    result['dkim_reason'] = dkim_reason

    # Overall: pass if at least one passes, or if both are neutral
    if sender_domain:
        result['overall_pass'] = result['spf_pass'] or result['dkim_pass']
    else:
        result['overall_pass'] = result['dkim_pass']

    return result
