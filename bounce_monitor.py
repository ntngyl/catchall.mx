#!/usr/bin/env python3
"""
Bounce rate monitor for CatchAll.mx
Auto-blocks domains with excessive bounces to protect IP reputation.
Run from cron hourly.
"""

import re
import redis
import subprocess
import logging
from datetime import datetime, timedelta

logging.basicConfig(
    filename='/var/log/catchall/bounce_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

r = redis.Redis(decode_responses=True)

# Thresholds
BOUNCE_RATE_THRESHOLD = 30   # Block if >30% bounces
MIN_EMAILS_FOR_BLOCK = 10    # Need at least 10 emails before blocking
BLOCK_DURATION_DAYS = 7


def get_mail_log_lines(hours=24):
    """Read mail.log entries from the last N hours."""
    try:
        result = subprocess.run(
            ['journalctl', '-u', 'postfix', '--since', f'{hours} hours ago', '--no-pager'],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout.split('\n')
    except Exception:
        pass

    # Fallback to /var/log/mail.log
    try:
        with open('/var/log/mail.log', 'r') as f:
            lines = f.readlines()
        # Filter to last 24h roughly (last 5000 lines)
        return lines[-5000:]
    except Exception as e:
        logging.error(f"Could not read mail log: {e}")
        return []


def analyze_bounces(lines):
    """
    Parse log lines and count sent vs bounced per domain.
    Returns: dict {domain: {'sent': int, 'bounced': int}}
    """
    stats = {}

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Extract domain from recipient
        domain_match = re.search(r'to=<[^@]+@([^>]+)>', line)
        if not domain_match:
            continue
        domain = domain_match.group(1).lower()

        if domain not in stats:
            stats[domain] = {'sent': 0, 'bounced': 0}

        if 'status=bounced' in line or 'status=5.' in line:
            stats[domain]['bounced'] += 1
        elif 'status=sent' in line or 'forwarded' in line.lower():
            stats[domain]['sent'] += 1

    return stats


def should_block_domain(sent, bounced):
    """Check if bounce rate exceeds threshold."""
    total = sent + bounced
    if total < MIN_EMAILS_FOR_BLOCK:
        return False
    rate = (bounced / total) * 100
    return rate > BOUNCE_RATE_THRESHOLD


def block_domain(domain, reason):
    """Block a domain in Redis."""
    block_key = f"bounce_block:{domain}"
    r.setex(block_key, BLOCK_DURATION_DAYS * 86400, reason)
    logging.warning(f"BLOCKED {domain}: {reason}")


def check_blocked_domains():
    """List currently bounce-blocked domains."""
    keys = r.keys('bounce_block:*')
    blocked = []
    for key in keys:
        domain = key.split(':', 1)[1]
        ttl = r.ttl(key)
        reason = r.get(key)
        blocked.append((domain, reason, ttl))
    return blocked


def main():
    lines = get_mail_log_lines(hours=24)
    if not lines:
        logging.info("No log lines to analyze")
        return

    stats = analyze_bounces(lines)
    blocked_today = 0

    for domain, counts in stats.items():
        sent = counts['sent']
        bounced = counts['bounced']
        total = sent + bounced

        if total < MIN_EMAILS_FOR_BLOCK:
            continue

        rate = (bounced / total) * 100
        logging.info(f"{domain}: {sent} sent, {bounced} bounced ({rate:.1f}%)")

        if should_block_domain(sent, bounced):
            reason = f"{bounced}/{total} bounces ({rate:.1f}%) in 24h"
            block_domain(domain, reason)
            blocked_today += 1

    # Summary
    already_blocked = check_blocked_domains()
    logging.info(f"Analysis complete. Blocked {blocked_today} new domains. {len(already_blocked)} total blocked.")

    # Clean up old entries (optional: keep blocked domains longer)
    for key in r.keys('limit:*'):
        r.delete(key)
    logging.info("Cleaned up old rate limit counters")


if __name__ == '__main__':
    main()
