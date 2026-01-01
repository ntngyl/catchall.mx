#!/usr/bin/env python3
"""
CatchAll.mx - Email Forwarding Module
Handles SMTP delivery to destination mail servers
"""

import smtplib
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

DOMAIN = os.getenv('DOMAIN', 'catchall.mx')

def get_mx_servers(domain):
    """Get MX servers for a domain, sorted by priority"""
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return sorted([(r.preference, str(r.exchange).rstrip('.')) for r in answers])
    except:
        return []

def forward_email(email_content, forward_to, sender, domain):
    """
    Forward email to destination via SMTP
    Returns True on success, False on failure
    """

    dest_domain = forward_to.split('@')[1]
    mx_servers = get_mx_servers(dest_domain)

    if not mx_servers:
        logging.error(f"No MX servers found for {dest_domain}")
        return False

    # Try each MX server in order of priority
    for priority, mx_host in mx_servers:
        try:
            logging.info(f"Forwarding queued email to {forward_to} via {mx_host}")

            server = smtplib.SMTP(mx_host, 25, timeout=30)
            server.ehlo(f'mail.{DOMAIN}')

            # Try STARTTLS if available
            try:
                server.starttls()
                server.ehlo(f'mail.{DOMAIN}')
            except:
                pass

            server.sendmail(
                f"forwarded@{DOMAIN}",
                [forward_to],
                email_content
            )
            server.quit()

            logging.info(f"Successfully forwarded queued email to {forward_to}")
            return True

        except Exception as e:
            logging.error(f"Failed to send via {mx_host}: {str(e)}")
            continue

    logging.error(f"Failed to forward to {forward_to} - all MX servers failed")
    return False
