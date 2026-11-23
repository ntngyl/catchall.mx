#!/usr/bin/env python3
"""
Email forwarding module
"""

import smtplib
import dns.resolver
import logging

# Outbound SMTP must leave over IPv4: SPF for catchall.mx lists only the IPv4
# address and the IPv6 address has no PTR. Binding to an IPv4 wildcard makes
# smtplib skip the AAAA results and connect over IPv4.
IPV4_ONLY = ('0.0.0.0', 0)

logging.basicConfig(
    filename='/var/log/catchall/forwarder.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_mx_servers(domain):
    """Get MX servers for a domain"""
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
    
    # Get destination domain and MX servers
    dest_domain = forward_to.split('@')[1]
    mx_servers = get_mx_servers(dest_domain)
    
    if not mx_servers:
        logging.error(f"No MX servers found for {dest_domain}")
        return False
    
    # Try each MX server
    for priority, mx_host in mx_servers:
        try:
            logging.info(f"Forwarding queued email to {forward_to} via {mx_host}")
            
            server = smtplib.SMTP(mx_host, 25, timeout=30, source_address=IPV4_ONLY)
            server.ehlo('mail.catchall.mx')
            
            # Try STARTTLS if available
            try:
                server.starttls()
                server.ehlo('mail.catchall.mx')
            except:
                pass
            
            # Send the email
            server.sendmail(
                f"forwarded@catchall.mx",
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
