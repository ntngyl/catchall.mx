#!/usr/bin/env python3
"""
CatchAll.mx - Main Email Processor with DKIM Signing
Called by Postfix for each incoming email
"""
import sys
import smtplib
import redis
import time
import dns.resolver
import logging
import os
from spam_detector import should_block_spam, should_quarantine, validate_sender_authenticity
from abuse import is_abuse_blocked
from from_rewrite import prepare_for_forward

# Postfix pipe(8) treats this exit status as a temporary failure: the message
# stays in the Postfix queue and is retried instead of being bounced/lost.
EX_TEMPFAIL = 75

# Outbound SMTP must leave over IPv4: SPF for catchall.mx lists only the IPv4
# address and the IPv6 address has no PTR. Binding to an IPv4 wildcard makes
# smtplib skip the AAAA results and connect over IPv4.
IPV4_ONLY = ('0.0.0.0', 0)

logging.basicConfig(
    filename='/var/log/catchall/forwarder.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

r = redis.Redis(host='localhost', port=6379, decode_responses=True)

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

    last_active = int(active_ts)
    inactive_seconds = time.time() - last_active
    inactive_days = inactive_seconds / 86400

    if inactive_days > 30:
        log(f"Domain {domain} inactive for {int(inactive_days)} days, requiring re-verification")
        r.delete(f"active:{domain}")
        return False

    return True

def is_dkim_enabled(domain):
    """Check if DKIM is enabled for a domain"""
    return r.exists(f"dkim:{domain}")

def queue_email_and_verify(domain, recipient, email_content):
    """Queue email and trigger verification"""
    from queue_manager import queue_email
    from verification import trigger_verification

    email_id = queue_email(domain, email_content)
    if not email_id:
        log(f"Failed to queue email for {domain} - queue full")
        sys.exit(1)

    log(f"Queued email {email_id} for unverified domain {domain}")

    if not r.exists(f"verify:{domain}"):
        forward_to = get_forward_address(domain)
        if forward_to:
            trigger_verification(domain, forward_to)
            log(f"Triggered verification for {domain}")

    sys.exit(0)

def forward_email_now(domain, forward_to, email_content):
    """Forward email immediately via SMTP with optional DKIM signing"""

    # Keep the From: header DMARC-aligned. When the original sender's DKIM
    # cannot carry alignment, From is rewritten and the message is signed
    # with the domain's own DKIM key if enabled, else as catchall.mx.
    signed_content = prepare_for_forward(email_content, domain)

    dest_domain = forward_to.split('@')[1]
    mx_servers = get_mx_servers(dest_domain)

    if not mx_servers:
        log(f"No MX servers found for {dest_domain} - deferring for retry")
        sys.exit(EX_TEMPFAIL)

    for priority, mx_host in mx_servers:
        try:
            log(f"Connecting to {mx_host} for {dest_domain}")

            server = smtplib.SMTP(mx_host, 25, timeout=30, source_address=IPV4_ONLY)
            server.ehlo('mail.catchall.mx')

            try:
                server.starttls()
                server.ehlo('mail.catchall.mx')
            except:
                pass

            # Send signed email
            if isinstance(signed_content, bytes):
                server.sendmail(
                    f"forwarded@catchall.mx",
                    [forward_to],
                    signed_content
                )
            else:
                server.sendmail(
                    f"forwarded@catchall.mx",
                    [forward_to],
                    signed_content.encode('utf-8')
                )
            server.quit()

            log(f"Successfully forwarded to {forward_to} via {mx_host}")

            # Update activity timestamp
            r.set(f"active:{domain}", int(time.time()))

            sys.exit(0)

        except Exception as e:
            log(f"Failed to send via {mx_host}: {str(e)}")
            continue

    log(f"Failed to forward to {forward_to} - all MX servers failed, deferring for retry")
    sys.exit(EX_TEMPFAIL)

def main():
    if len(sys.argv) < 2:
        log("Error: No recipient specified")
        sys.exit(1)

    recipient = sys.argv[1]
    domain = recipient.split('@')[1]

    log(f"Processing email for {recipient} (domain: {domain})")

    forward_to = get_forward_address(domain)
    if not forward_to:
        log(f"No forward address found for {domain}")
        sys.exit(0)

    log(f"Forward address: {forward_to}")

    if is_abuse_blocked(domain, forward_to):
        log(f"Domain {domain} / target {forward_to} is on the abuse blocklist - discarding email")
        sys.exit(0)

    if is_blocked(domain, forward_to):
        log(f"Domain {domain} is BLOCKED by {forward_to} - discarding email")
        sys.exit(0)

    # Read raw bytes: mail is not always valid UTF-8, and a strict decode
    # would crash the forwarder (surrogateescape round-trips every byte).
    email_content = sys.stdin.buffer.read().decode('utf-8', 'surrogateescape')

    # Parse subject for spam detection
    subject = ''
    for line in email_content.split('\n'):
        if line.lower().startswith('subject:'):
            subject = line.split(':', 1)[1].strip()
            break

    # Get spam level from DNS
    spam_level = 'moderate'
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('catchall-spam='):
                spam_level = txt.split('=', 1)[1].strip()
                break
    except:
        pass

    # Block obvious spam/phishing
    if should_block_spam(email_content, subject, spam_level):
        log(f"SPAM/PHISHING detected for {domain}, discarding")
        sys.exit(0)

    # Check sender authenticity (SPF + DKIM)
    auth_result = validate_sender_authenticity(email_content)
    if not auth_result['overall_pass']:
        log(f"Sender auth failed for {domain}: SPF={auth_result['spf_reason']}, DKIM={auth_result['dkim_reason']}")
        quarantine, score = should_quarantine(email_content, subject, spam_level)
        if quarantine:
            log(f"Quarantining email for {domain} (score={score})")
            from quarantine_manager import quarantine_email
            quarantine_email(domain, email_content, reason='sender_auth_fail', score=score)
            sys.exit(0)

    if not is_verified(domain):
        log(f"Domain {domain} not verified - queueing email")
        queue_email_and_verify(domain, recipient, email_content)
    else:
        dkim_status = "with DKIM" if is_dkim_enabled(domain) else "without DKIM"
        log(f"Domain {domain} verified - forwarding immediately {dkim_status}")
        forward_email_now(domain, forward_to, email_content)

if __name__ == '__main__':
    main()
