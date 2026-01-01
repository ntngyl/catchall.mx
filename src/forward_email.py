#!/usr/bin/env python3
"""
CatchAll.mx - Main Email Processor
Called by Postfix for each incoming email
"""
import sys
import smtplib
import redis
import time
import dns.resolver
import logging
import os

# Load environment
from dotenv import load_dotenv
load_dotenv('/etc/catchall.env')

logging.basicConfig(
    filename='/var/log/catchall/forwarder.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

r = redis.Redis(
    host=os.getenv('REDIS_HOST', 'localhost'),
    port=int(os.getenv('REDIS_PORT', 6379)),
    decode_responses=True
)

def log(message):
    logging.info(message)

def get_forward_address(domain):
    """Get forward address from DNS TXT record"""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if 'catchall-forward=' in txt:
                return txt.split('catchall-forward=')[1].split()[0]
    except:
        pass
    return None

def get_mx_servers(domain):
    """Get MX servers for a domain, sorted by priority"""
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return sorted([(r.preference, str(r.exchange).rstrip('.')) for r in answers])
    except:
        return []

def is_blocked(domain, recipient_email):
    """Check if domain is blocked by the recipient"""
    return r.exists(f"block:{domain}:{recipient_email}")

def is_verified(domain):
    """Check if domain is verified and not inactive"""
    active_ts = r.get(f"active:{domain}")
    if not active_ts:
        return False

    # Check inactivity (30 days)
    last_active = int(active_ts)
    inactive_seconds = time.time() - last_active
    inactive_days = inactive_seconds / 86400

    if inactive_days > 30:
        log(f"Domain {domain} inactive for {int(inactive_days)} days, requiring re-verification")
        r.delete(f"active:{domain}")
        return False

    return True

def queue_email_and_verify(domain, recipient, email_content):
    """Queue email and trigger verification"""
    from queue_manager import queue_email
    from verification import trigger_verification

    # Queue the email
    email_id = queue_email(domain, email_content)
    if not email_id:
        log(f"Failed to queue email for {domain} - queue full")
        sys.exit(1)

    log(f"Queued email {email_id} for unverified domain {domain}")

    # Trigger verification if not already pending
    if not r.exists(f"verify:{domain}"):
        forward_to = get_forward_address(domain)
        if forward_to:
            trigger_verification(domain, forward_to)
            log(f"Triggered verification for {domain}")

    sys.exit(0)

def forward_email_now(domain, forward_to, email_content):
    """Forward email immediately via SMTP"""

    dest_domain = forward_to.split('@')[1]
    mx_servers = get_mx_servers(dest_domain)

    if not mx_servers:
        log(f"No MX servers found for {dest_domain}")
        sys.exit(1)

    # Try each MX server
    for priority, mx_host in mx_servers:
        try:
            log(f"Connecting to {mx_host} for {dest_domain}")

            server = smtplib.SMTP(mx_host, 25, timeout=30)
            server.ehlo(os.getenv('DOMAIN', 'catchall.mx'))

            try:
                server.starttls()
                server.ehlo(os.getenv('DOMAIN', 'catchall.mx'))
            except:
                pass

            server.sendmail(
                f"forwarded@{os.getenv('DOMAIN', 'catchall.mx')}",
                [forward_to],
                email_content
            )
            server.quit()

            log(f"Successfully forwarded to {forward_to} via {mx_host}")

            # Update activity timestamp
            r.set(f"active:{domain}", int(time.time()))
            sys.exit(0)

        except Exception as e:
            log(f"Failed to send via {mx_host}: {str(e)}")
            continue

    log(f"Failed to forward to {forward_to} - all MX servers failed")
    sys.exit(1)

def main():
    if len(sys.argv) < 2:
        log("Error: No recipient specified")
        sys.exit(1)

    recipient = sys.argv[1]
    domain = recipient.split('@')[1]

    log(f"Processing email for {recipient} (domain: {domain})")

    # Get forward address from DNS
    forward_to = get_forward_address(domain)
    if not forward_to:
        log(f"No forward address found for {domain}")
        sys.exit(0)

    log(f"Forward address: {forward_to}")

    # Check if domain is blocked
    if is_blocked(domain, forward_to):
        log(f"Domain {domain} is BLOCKED by {forward_to} - discarding email")
        sys.exit(0)

    # Read email from stdin
    email_content = sys.stdin.read()

    # Check verification status
    if not is_verified(domain):
        log(f"Domain {domain} not verified - queueing email")
        queue_email_and_verify(domain, recipient, email_content)
    else:
        log(f"Domain {domain} verified - forwarding immediately")
        forward_email_now(domain, forward_to, email_content)

if __name__ == '__main__':
    main()
