#!/usr/bin/env python3
"""
Email queue management during verification
"""

import os
import hashlib
import time
import logging
import redis

QUEUE_DIR = '/var/spool/catchall/queue'
MAX_QUEUE_SIZE = 100
# Unconfirmed mail is held for 24 hours at most, then deleted (zero retention)
QUEUE_TTL = 24 * 3600

logging.basicConfig(
    filename='/var/log/catchall/queue.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

r = redis.Redis(decode_responses=True)

def queue_email(domain, email_data):
    """
    Store email to disk and track in Redis
    Returns email_id or None if queue full
    """
    queue_key = f"queue:{domain}"
    current_size = r.llen(queue_key)

    if current_size >= MAX_QUEUE_SIZE:
        logging.warning(f"Queue full for {domain}")
        return None

    # Generate unique ID
    email_id = hashlib.md5(
        f"{domain}{time.time()}".encode()
    ).hexdigest()

    # Create domain directory
    domain_dir = os.path.join(QUEUE_DIR, domain)
    os.makedirs(domain_dir, exist_ok=True)
    # The pipe (nobody) writes the queue; the web service (www-data, member of
    # the same group) must be able to read and remove it when the destination
    # clicks Accept. Without this the queue was only flushed by the nightly cron.
    try:
        os.chmod(domain_dir, 0o770)
    except OSError:
        pass

    # Save to disk
    email_path = os.path.join(domain_dir, f"{email_id}.eml")
    with open(email_path, 'w', encoding='utf-8', errors='surrogateescape') as f:
        f.write(email_data)
    try:
        os.chmod(email_path, 0o660)
    except OSError:
        pass

    # Track in Redis
    r.rpush(queue_key, email_id)
    r.expire(queue_key, QUEUE_TTL)

    logging.info(f"Queued email for {domain}: {email_id} (added to Redis)")
    return email_id

def flush_queue(domain, forward_to):
    """
    Forward all queued emails and cleanup
    Checks both Redis list AND disk directory for queued emails
    Returns count of emails forwarded
    """
    from forwarder import forward_email

    # A queue is named after the domain, or domain~<hash> for a routed destination
    real_domain = domain.split('~', 1)[0]
    queue_key = f"queue:{domain}"

    # Get email IDs from Redis
    redis_email_ids = set(r.lrange(queue_key, 0, -1))
    logging.info(f"Found {len(redis_email_ids)} emails in Redis for {domain}")

    # Also check disk directory for any orphaned emails
    domain_dir = os.path.join(QUEUE_DIR, domain)
    disk_email_ids = set()

    if os.path.exists(domain_dir) and os.path.isdir(domain_dir):
        for filename in os.listdir(domain_dir):
            if filename.endswith('.eml'):
                email_id = filename[:-4]  # Remove .eml extension
                disk_email_ids.add(email_id)
        logging.info(f"Found {len(disk_email_ids)} emails on disk for {domain}")

    # Combine both sources (Redis + disk)
    all_email_ids = redis_email_ids | disk_email_ids
    logging.info(f"Total unique emails to forward: {len(all_email_ids)}")

    count = 0
    failed_ids = []
    for email_id in all_email_ids:
        email_path = os.path.join(domain_dir, f"{email_id}.eml")

        if os.path.exists(email_path):
            try:
                logging.info(f"Forwarding queued email: {email_id}")
                with open(email_path, 'r', encoding='utf-8', errors='surrogateescape') as f:
                    email_data = f.read()

                if forward_email(email_data, forward_to, f"queued@{real_domain}", real_domain):
                    count += 1
                    logging.info(f"Successfully forwarded: {email_id}")
                    os.remove(email_path)
                    logging.info(f"Removed queued file: {email_id}")
                else:
                    # Keep the file so the email is not lost; the daily
                    # retry (retry_active_queues) picks it up again.
                    failed_ids.append(email_id)
                    logging.error(f"Failed to forward, keeping for retry: {email_id}")
            except Exception as e:
                failed_ids.append(email_id)
                logging.error(f"Error flushing {email_id}: {e}")
        else:
            logging.warning(f"Email file not found on disk: {email_id}")

    # Cleanup Redis, keeping only the emails that still need a retry
    r.delete(queue_key)
    if failed_ids:
        r.rpush(queue_key, *failed_ids)
        r.expire(queue_key, QUEUE_TTL)

    # Cleanup directory (only succeeds once it is empty)
    try:
        os.rmdir(domain_dir)
        logging.info(f"Removed queue directory for {domain}")
    except:
        pass

    logging.info(f"Flushed {count} emails for {domain}, {len(failed_ids)} kept for retry")
    return count

def retry_active_queues():
    """Retry queued emails left behind for destinations that are already verified (cron job)"""
    from abuse import is_abuse_blocked
    from routing import load_config, split_queue_name, target_for_queue, has_consent

    if not os.path.exists(QUEUE_DIR):
        return

    for name in os.listdir(QUEUE_DIR):
        domain, _ = split_queue_name(name)
        if not r.exists(f"active:{domain}"):
            continue

        cfg = load_config(domain)
        if cfg.lookup_failed:
            continue
        forward_to = target_for_queue(name, cfg)

        if (forward_to and has_consent(domain, forward_to, cfg.forward)
                and not is_abuse_blocked(domain, forward_to)):
            flush_queue(name, forward_to)

def cleanup_expired_queues():
    """Cleanup old queued emails (cron job)"""
    if not os.path.exists(QUEUE_DIR):
        return

    for domain in os.listdir(QUEUE_DIR):
        domain_dir = os.path.join(QUEUE_DIR, domain)
        if not os.path.isdir(domain_dir):
            continue

        for email_file in os.listdir(domain_dir):
            email_path = os.path.join(domain_dir, email_file)

            # Delete files older than the queue lifetime
            if os.path.getmtime(email_path) < (time.time() - QUEUE_TTL):
                try:
                    os.remove(email_path)
                    logging.info(f"Cleaned up expired: {email_path}")
                except:
                    pass

if __name__ == '__main__':
    cleanup_expired_queues()
    retry_active_queues()
