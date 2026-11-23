#!/usr/bin/env python3
"""
Process incoming emails and forward them
Reads email from stdin (called by Postfix)
"""

import sys
import email
import redis
import dns.resolver
import logging
from forwarder import forward_email

logging.basicConfig(
    filename='/var/log/catchall/processor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

r = redis.Redis(decode_responses=True)

def get_forward_address(domain):
    """Get forward address from DNS TXT records"""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('catchall-forward='):
                return txt.split('=', 1)[1]
    except Exception as e:
        logging.error(f"DNS lookup failed for {domain}: {e}")
    return None

# Read email from stdin
email_data = sys.stdin.read()

try:
    # Parse email
    msg = email.message_from_string(email_data)
    to_address = msg.get('To', '')
    
    if '@' not in to_address:
        logging.error(f"Invalid To address: {to_address}")
        sys.exit(0)
    
    domain = to_address.split('@')[1].strip('>').strip('<')
    
    # Get forward address from DNS
    forward_to = get_forward_address(domain)
    
    if not forward_to:
        logging.error(f"No forward address found for {domain}")
        sys.exit(0)
    
    # Forward the email
    logging.info(f"Forwarding email for {domain} to {forward_to}")
    
    if forward_email(email_data, forward_to, to_address, domain):
        logging.info(f"Successfully forwarded email for {domain}")
        sys.exit(0)
    else:
        logging.error(f"Failed to forward email for {domain}")
        sys.exit(75)  # Temporary failure, Postfix will retry

except Exception as e:
    logging.error(f"Error processing email: {e}")
    import traceback
    logging.error(traceback.format_exc())
    sys.exit(75)  # Temporary failure
