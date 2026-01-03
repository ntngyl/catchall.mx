#!/usr/bin/env python3
"""
CatchAll.mx - DKIM Key Manager
Generates and manages DKIM keys for user domains
"""

import os
import subprocess
import logging
import redis
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64

# Configuration
DKIM_KEYS_DIR = '/opt/catchall/dkim_keys'
DKIM_SELECTOR = 'catchall'
KEY_SIZE = 2048

logging.basicConfig(
    filename='/var/log/catchall/dkim.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

r = redis.Redis(host='localhost', port=6379, decode_responses=True)

def ensure_keys_dir():
    """Create DKIM keys directory if it doesn't exist"""
    if not os.path.exists(DKIM_KEYS_DIR):
        os.makedirs(DKIM_KEYS_DIR, mode=0o700)
        logging.info(f"Created DKIM keys directory: {DKIM_KEYS_DIR}")

def get_key_paths(domain):
    """Get paths for private and public key files"""
    safe_domain = domain.replace('/', '_').replace('..', '_')
    private_key_path = os.path.join(DKIM_KEYS_DIR, f"{safe_domain}.private")
    public_key_path = os.path.join(DKIM_KEYS_DIR, f"{safe_domain}.public")
    return private_key_path, public_key_path

def generate_dkim_key(domain):
    """
    Generate DKIM key pair for a domain
    Returns (success, dns_record or error_message)
    """
    ensure_keys_dir()

    private_key_path, public_key_path = get_key_paths(domain)

    # Check if key already exists
    if os.path.exists(private_key_path):
        logging.info(f"DKIM key already exists for {domain}")
        return get_dns_record(domain)

    try:
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=KEY_SIZE,
            backend=default_backend()
        )

        # Get public key
        public_key = private_key.public_key()

        # Serialize private key (PEM format)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Serialize public key (PEM format)
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Save private key (restricted permissions)
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        os.chmod(private_key_path, 0o600)

        # Save public key
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
        os.chmod(public_key_path, 0o644)

        logging.info(f"Generated DKIM key pair for {domain}")

        # Return DNS record
        return get_dns_record(domain)

    except Exception as e:
        logging.error(f"Failed to generate DKIM key for {domain}: {e}")
        return False, str(e)

def get_dns_record(domain):
    """
    Get the DNS TXT record value for a domain's DKIM
    Returns (success, dns_record_info)
    """
    private_key_path, public_key_path = get_key_paths(domain)

    if not os.path.exists(public_key_path):
        return False, "DKIM key not found. Please generate first."

    try:
        with open(public_key_path, 'rb') as f:
            public_pem = f.read()

        # Extract the base64 part (remove headers/footers)
        lines = public_pem.decode('utf-8').strip().split('\n')
        # Remove BEGIN and END lines
        key_lines = [l for l in lines if not l.startswith('-----')]
        public_key_b64 = ''.join(key_lines)

        # Format DNS record
        dns_host = f"{DKIM_SELECTOR}._domainkey"
        dns_value = f"v=DKIM1; k=rsa; p={public_key_b64}"

        return True, {
            'host': dns_host,
            'full_host': f"{dns_host}.{domain}",
            'type': 'TXT',
            'value': dns_value,
            'selector': DKIM_SELECTOR
        }

    except Exception as e:
        logging.error(f"Failed to read DKIM public key for {domain}: {e}")
        return False, str(e)

def verify_dkim_dns(domain):
    """
    Verify that the DKIM DNS record is correctly configured
    Returns (success, message)
    """
    import dns.resolver

    private_key_path, public_key_path = get_key_paths(domain)

    if not os.path.exists(public_key_path):
        return False, "DKIM key not generated for this domain"

    # Get expected public key
    success, record_info = get_dns_record(domain)
    if not success:
        return False, record_info

    expected_value = record_info['value']
    dns_name = f"{DKIM_SELECTOR}._domainkey.{domain}"

    try:
        answers = dns.resolver.resolve(dns_name, 'TXT')

        for rdata in answers:
            txt_value = ''.join([s.decode('utf-8') if isinstance(s, bytes) else s for s in rdata.strings])

            # Check if public key matches
            if 'p=' in txt_value and 'p=' in expected_value:
                dns_key = txt_value.split('p=')[1].split(';')[0].strip()
                expected_key = expected_value.split('p=')[1].split(';')[0].strip()

                if dns_key == expected_key:
                    # Mark domain as DKIM enabled in Redis
                    r.set(f"dkim:{domain}", "enabled")
                    logging.info(f"DKIM verified and enabled for {domain}")
                    return True, "DKIM verified successfully! Emails will now be signed."

        return False, "DKIM record found but public key doesn't match. Please check the record."

    except dns.resolver.NXDOMAIN:
        return False, f"DNS record not found: {dns_name}"
    except dns.resolver.NoAnswer:
        return False, f"No TXT record found at {dns_name}"
    except Exception as e:
        logging.error(f"DKIM DNS verification failed for {domain}: {e}")
        return False, f"DNS lookup error: {str(e)}"

def is_dkim_enabled(domain):
    """Check if DKIM is enabled for a domain"""
    return r.exists(f"dkim:{domain}")

def get_private_key_path(domain):
    """Get private key path for signing (used by OpenDKIM)"""
    private_key_path, _ = get_key_paths(domain)
    if os.path.exists(private_key_path):
        return private_key_path
    return None

def disable_dkim(domain):
    """Disable DKIM for a domain"""
    r.delete(f"dkim:{domain}")
    logging.info(f"DKIM disabled for {domain}")
    return True

def list_dkim_domains():
    """List all domains with DKIM enabled"""
    keys = r.keys("dkim:*")
    return [k.replace("dkim:", "") for k in keys]

if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python dkim_manager.py <command> [domain]")
        print("Commands: generate, verify, status, list")
        sys.exit(1)

    command = sys.argv[1]

    if command == 'list':
        domains = list_dkim_domains()
        print(f"DKIM enabled domains: {domains}")

    elif len(sys.argv) < 3:
        print("Domain required for this command")
        sys.exit(1)

    else:
        domain = sys.argv[2]

        if command == 'generate':
            success, result = generate_dkim_key(domain)
            if success:
                print(f"DKIM key generated for {domain}")
                print(f"\nAdd this DNS record:")
                print(f"  Type: TXT")
                print(f"  Host: {result['host']}")
                print(f"  Value: {result['value']}")
            else:
                print(f"Error: {result}")

        elif command == 'verify':
            success, message = verify_dkim_dns(domain)
            print(message)

        elif command == 'status':
            if is_dkim_enabled(domain):
                print(f"DKIM is ENABLED for {domain}")
            else:
                print(f"DKIM is NOT enabled for {domain}")

        else:
            print(f"Unknown command: {command}")
