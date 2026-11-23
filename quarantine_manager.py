#!/usr/bin/env python3
"""
Quarantine management for CatchAll.mx
Stores suspicious emails separately from verification queue.
"""

import os
import hashlib
import time
import logging
import redis

QUARANTINE_DIR = '/var/spool/catchall/quarantine'
MAX_QUARANTINE_SIZE = 500

logging.basicConfig(
    filename='/var/log/catchall/quarantine.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

r = redis.Redis(decode_responses=True)


def quarantine_email(domain, email_content, reason='spam', score=0):
    """
    Store suspicious email to quarantine and track in Redis.
    Returns email_id or None if quarantine full.
    """
    q_key = f"quarantine:{domain}"
    total_size = sum(r.llen(f"quarantine:{d}") for d in r.keys("quarantine:*"))

    if total_size >= MAX_QUARANTINE_SIZE:
        logging.warning("Global quarantine full, dropping oldest")
        _drop_oldest()

    email_id = hashlib.md5(
        f"quarantine:{domain}{time.time()}".encode()
    ).hexdigest()

    domain_dir = os.path.join(QUARANTINE_DIR, domain)
    os.makedirs(domain_dir, exist_ok=True)

    email_path = os.path.join(domain_dir, f"{email_id}.eml")
    with open(email_path, 'w') as f:
        f.write(email_content)

    # Track in Redis with metadata
    r.rpush(q_key, email_id)
    r.hset(f"quarantine:meta:{email_id}", mapping={
        'domain': domain,
        'reason': reason,
        'score': str(score),
        'timestamp': str(int(time.time())),
        'status': 'pending',
    })
    r.expire(q_key, 7 * 86400)

    logging.info(f"Quarantined {email_id} for {domain}: {reason} (score={score})")
    return email_id


def get_quarantined_emails(domain=None):
    """List quarantined emails. If domain is None, list all."""
    results = []
    if domain:
        domains = [domain]
    else:
        domains = [d for d in os.listdir(QUARANTINE_DIR) if os.path.isdir(os.path.join(QUARANTINE_DIR, d))]

    for d in domains:
        q_key = f"quarantine:{d}"
        email_ids = r.lrange(q_key, 0, -1)
        for eid in email_ids:
            meta = r.hgetall(f"quarantine:meta:{eid}") or {}
            email_path = os.path.join(QUARANTINE_DIR, d, f"{eid}.eml")
            if os.path.exists(email_path):
                meta['email_id'] = eid
                meta['domain'] = d
                meta['path'] = email_path
                results.append(meta)

    return sorted(results, key=lambda x: x.get('timestamp', '0'), reverse=True)


def release_email(email_id, forward_to):
    """Release a quarantined email and forward it."""
    meta = r.hgetall(f"quarantine:meta:{email_id}")
    if not meta:
        return False, "Email not found"

    domain = meta.get('domain', '')
    email_path = os.path.join(QUARANTINE_DIR, domain, f"{email_id}.eml")

    if not os.path.exists(email_path):
        return False, "Email file missing"

    with open(email_path, 'r') as f:
        email_content = f.read()

    # Forward via existing forwarder
    from forwarder import forward_email
    success = forward_email(email_content, forward_to, f"quarantine-release@{domain}", domain)

    if success:
        r.hset(f"quarantine:meta:{email_id}", 'status', 'released')
        os.remove(email_path)
        r.lrem(f"quarantine:{domain}", 0, email_id)
        logging.info(f"Released {email_id} to {forward_to}")
        return True, "Released and forwarded"
    else:
        return False, "Failed to forward"


def delete_email(email_id):
    """Delete a quarantined email permanently."""
    meta = r.hgetall(f"quarantine:meta:{email_id}")
    if not meta:
        return False, "Email not found"

    domain = meta.get('domain', '')
    email_path = os.path.join(QUARANTINE_DIR, domain, f"{email_id}.eml")

    if os.path.exists(email_path):
        os.remove(email_path)

    r.lrem(f"quarantine:{domain}", 0, email_id)
    r.delete(f"quarantine:meta:{email_id}")
    logging.info(f"Deleted quarantined email {email_id}")
    return True, "Deleted"


def get_email_content(email_id):
    """Read full content of a quarantined email."""
    meta = r.hgetall(f"quarantine:meta:{email_id}")
    if not meta:
        return None

    domain = meta.get('domain', '')
    email_path = os.path.join(QUARANTINE_DIR, domain, f"{email_id}.eml")
    if os.path.exists(email_path):
        with open(email_path, 'r') as f:
            return f.read()
    return None


def _drop_oldest():
    """Remove oldest quarantined email to make room."""
    all_emails = get_quarantined_emails()
    if all_emails:
        oldest = all_emails[-1]
        delete_email(oldest['email_id'])


def cleanup_expired():
    """Remove quarantined emails older than 7 days."""
    cutoff = time.time() - 7 * 86400
    all_emails = get_quarantined_emails()
    for meta in all_emails:
        ts = int(meta.get('timestamp', 0))
        if ts < cutoff:
            delete_email(meta['email_id'])
            logging.info(f"Cleaned up expired quarantine {meta['email_id']}")


if __name__ == '__main__':
    cleanup_expired()
