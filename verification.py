#!/usr/bin/env python3
"""
Email verification handling - Spam prevention
Uses Accumbamail SMTP for sending verification emails
"""

import secrets
import logging
import redis
import time
import smtplib
import dns.resolver
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import email.utils

logging.basicConfig(
    filename='/var/log/catchall/verification.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

r = redis.Redis(decode_responses=True)

# Mail submission: verification email is submitted to the LOCAL Postfix MTA
# (localhost:25), which queues it and relays to the recipient's MX. The former
# Accumbamail SMTP relay was dropped after its login started failing with
# "535 Authentication failed" (dead credentials; see forwarder.log from
# 2026-11-04 onward). NOTE: final delivery to Gmail destinations depends on the
# box's outbound reverse DNS (IPv6 PTR) being in place.
LOCAL_SMTP_HOST = "localhost"
LOCAL_SMTP_PORT = 10026  # outbound-only listener (master.cf); port 25 routes everything to catchall-pipe
FROM_EMAIL = "verify@catchall.mx"
FROM_NAME = "CatchAll.mx"

def trigger_verification(domain, recipient_email, key=None):
    """Send verification email and mark it as pending.

    key is the queue/verification name: the bare domain for the default
    destination, domain~<hash> for a routed destination (see routing.py).
    """
    key = key or domain

    # Check if already pending
    if r.exists(f"verify:{key}"):
        logging.info(f"Verification already pending for {key}")
        return False

    # Generate secure token
    token = secrets.token_urlsafe(32)

    # Get queue count
    queue_count = str(r.llen(f"queue:{key}") or 0)

    # Send verification email FIRST. Only persist the 7-day pending key if the
    # send actually succeeded; otherwise a transient/credential SMTP failure
    # would leave the key in place and block every retry for a day (the key
    # existence check in forward_email.py and above returns early).
    sent = send_verification_email(domain, recipient_email, token, queue_count, key)
    if not sent:
        logging.error(
            f"Verification email send FAILED for {domain}; not setting pending "
            f"key so the next inbound email can retry"
        )
        return False

    # Store verification status with token and recipient
    verify_data = f"pending:{token}:{recipient_email}"
    r.setex(
        f"verify:{key}",
        24 * 3600,  # 24 hours, the same as the queue lifetime
        verify_data
    )

    logging.info(f"Verification triggered for {domain}")
    return True

def request_confirmation(domain, target, default_target):
    """
    Send the confirmation email on request from the website, before any mail
    has arrived. Returns one of: confirmed, declined, recent, sent, failed.
    """
    from routing import has_consent, queue_name

    if r.exists(f"active:{domain}") and has_consent(domain, target, default_target):
        return 'confirmed'
    if r.exists(f"block:{domain}:{target}"):
        return 'declined'

    qname = queue_name(domain, target, default_target)
    sent_key = f"verify-sent:{qname}"
    if r.exists(sent_key):
        return 'recent'          # one email per destination every 10 minutes

    pending = r.get(f"verify:{qname}") or ''
    parts = pending.split(":", 2)
    if len(parts) == 3 and parts[0] == 'pending' and parts[2].strip().lower() == target.strip().lower():
        # A link is already out: send the same one again rather than invalidating it
        queue_count = str(r.llen(f"queue:{qname}") or 0)
        ok = send_verification_email(domain, target, parts[1], queue_count, qname)
    else:
        r.delete(f"verify:{qname}")
        ok = trigger_verification(domain, target, key=qname)

    if ok:
        r.setex(sent_key, 600, "1")
        return 'sent'
    return 'failed'

def send_verification_email(domain, recipient, token, queue_count, key=None):
    """Send verification email via Accumbamail SMTP"""

    key = key or domain
    accept_url = f"https://catchall.mx/verify/{key}?token={token}&action=accept"
    block_url = f"https://catchall.mx/verify/{key}?token={token}&action=block"

    # Create email message
    msg = MIMEMultipart('alternative')
    msg['Subject'] = f"Confirm email forwarding from {domain}"
    msg['From'] = f"{FROM_NAME} <{FROM_EMAIL}>"
    msg['To'] = recipient
    msg['Message-ID'] = email.utils.make_msgid(domain='catchall.mx')
    msg['Date'] = email.utils.formatdate(localtime=True)

    # Wording depends on whether mail is already waiting or the owner asked
    # for the confirmation from the website before any mail arrived.
    if str(queue_count) == "0":
        intro_text = (f"The domain {domain} has been set up to forward its email to your address "
                      f"({recipient}), and a confirmation was requested on catchall.mx.")
        intro_html = (f"The domain <strong>{domain}</strong> has been set up to forward its email to "
                      f"your address, and a confirmation was requested on catchall.mx:")
    else:
        intro_text = (f"Someone sent {queue_count} email(s) to an address at {domain}, which is "
                      f"configured to forward to your email ({recipient}).")
        intro_html = (f"Someone sent <strong>{queue_count}</strong> email(s) to an address at "
                      f"<strong>{domain}</strong>, which is configured to forward to your email:")

    # Plain text version
    text_body = f"""
Hi,

{intro_text}

To prevent spam, please confirm:

ACCEPT: {accept_url}
(Forward these and future emails from {domain})

BLOCK: {block_url}
(Block emails from {domain} - they will NOT be forwarded)

If you don't recognize {domain}, please click BLOCK.

This link expires in 24 hours. Emails waiting for it are deleted after that.

— CatchAll.mx
"""

    # HTML version
    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f5f5f5;">
    <div style="background: white; border-radius: 8px; padding: 40px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <h2 style="color: #333; margin-bottom: 20px;">Confirm Email Forwarding</h2>
        <p style="color: #666; font-size: 16px; line-height: 1.6;">
            {intro_html}
        </p>
        <p style="background: #f5f5f5; padding: 15px; border-left: 4px solid #2196F3; margin: 20px 0;">
            {recipient}
        </p>

        <p style="margin-top: 30px; font-size: 16px; font-weight: bold;">To prevent spam, please choose:</p>

        <div style="text-align: center; margin: 40px 0;">
            <a href="{accept_url}"
               style="background: #4CAF50; color: white; padding: 16px 40px;
                      text-decoration: none; border-radius: 6px; display: inline-block; margin: 10px;
                      font-weight: bold; font-size: 16px;">
                ✓ Accept &amp; Forward
            </a>
            <br><br>
            <a href="{block_url}"
               style="background: #f44336; color: white; padding: 16px 40px;
                      text-decoration: none; border-radius: 6px; display: inline-block; margin: 10px;
                      font-weight: bold; font-size: 16px;">
                ✕ Block {domain}
            </a>
        </div>

        <div style="background: #f9f9f9; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="color: #666; font-size: 14px; margin: 5px 0;">
                <strong>Accept:</strong> Forward these {queue_count} email(s) and all future emails from {domain}
            </p>
            <p style="color: #666; font-size: 14px; margin: 5px 0;">
                <strong>Block:</strong> Reject emails from {domain} - they will NOT be forwarded to you
            </p>
        </div>

        <p style="color: #999; font-size: 12px; margin-top: 30px;">
            If you don't recognize <strong>{domain}</strong>, please click <strong>Block</strong>.
        </p>

        <p style="color: #666; font-size: 12px; margin-top: 20px;">This link expires in 24 hours. Emails waiting for it are deleted after that.</p>
        <hr style="margin-top: 30px; border: none; border-top: 1px solid #ddd;">
        <p style="color: #999; font-size: 11px; text-align: center;">
            CatchAll.mx - Spam-free email forwarding
        </p>
    </div>
</body>
</html>
"""

    msg.attach(MIMEText(text_body, 'plain'))
    msg.attach(MIMEText(html_body, 'html'))

    try:
        logging.info(f"Sending verification to {recipient} via local Postfix")

        # Submit to the local Postfix MTA. 127.0.0.1 is in mynetworks, so the
        # message is accepted without auth/STARTTLS and bypasses postscreen;
        # Postfix then queues it and relays it to the recipient's MX.
        server = smtplib.SMTP(LOCAL_SMTP_HOST, LOCAL_SMTP_PORT, timeout=30)
        server.send_message(msg)
        server.quit()

        logging.info(f"Verification email accepted by local Postfix for {recipient}")
        return True

    except Exception as e:
        logging.error(f"Failed to submit verification email to local Postfix: {str(e)}")
        return False

def verify_domain_token(name, provided_token, action):
    """
    Verify with token and accept/block.
    name is the bare domain (default destination) or domain~<hash> (a routed
    destination). Returns (success, message)
    """
    from routing import load_config, split_queue_name, grant_consent

    domain, _ = split_queue_name(name)

    # Get stored verification data
    verify_data = r.get(f"verify:{name}")
    if not verify_data or not verify_data.startswith("pending:"):
        return False, "Invalid or expired verification link"

    # Parse: pending:token:recipient_email
    parts = verify_data.split(":", 2)
    if len(parts) != 3:
        return False, "Invalid verification data"

    stored_token = parts[1]
    recipient_email = parts[2]

    # Verify token matches
    if provided_token != stored_token:
        return False, "Invalid verification token"

    # Handle action
    if action == 'block':
        # Block this domain for this recipient
        r.set(f"block:{domain}:{recipient_email}", "1")
        r.delete(f"verify:{name}")
        r.delete(f"queue:{name}")

        logging.info(f"Domain {domain} BLOCKED by its destination")
        return True, f"<strong>{domain}</strong> has been blocked. You will NOT receive any emails from this domain."

    elif action == 'accept':
        from queue_manager import flush_queue

        # The address that clicked must still be a destination in the domain's DNS
        cfg = load_config(domain)
        if cfg.lookup_failed:
            return False, "Could not read the domain's DNS records. Please try the link again in a few minutes."
        if recipient_email.strip().lower() not in [t.lower() for t in cfg.targets()]:
            return False, "The domain's DNS no longer forwards to this address."

        # Mark as verified, and record that this destination agreed
        r.delete(f"verify:{name}")
        r.set(f"active:{domain}", int(time.time()))
        grant_consent(domain, recipient_email)

        # Flush the mail that was waiting for this destination
        count = flush_queue(name, recipient_email)

        logging.info(f"Domain {domain} ACCEPTED by its destination, forwarded {count} emails")
        if count:
            return True, f"<strong>{domain}</strong> verified! We've forwarded <strong>{count}</strong> email(s) to you. Future emails from this domain will be forwarded automatically."
        return True, f"<strong>{domain}</strong> is confirmed. Emails sent to this domain will now be forwarded to you automatically."

    else:
        return False, "Invalid action"
