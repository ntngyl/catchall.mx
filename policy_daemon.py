#!/usr/bin/env python3
"""
Catchall.mx Policy Daemon
Handles email routing decisions for Postfix
"""

import asyncio
import redis
import dns.resolver
import time
import logging
from datetime import datetime
from abuse import is_blocked_domain, is_blocked_target
from routing import load_config, resolve

# Configuration
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
POLICY_PORT = 10032

# Global limits
DEST_DAILY_LIMIT = 200       # Total emails/day to gmail.com, outlook.com, etc.
DEST_HOURLY_LIMIT = 50      # Hourly burst limit per destination domain
DISPOSABLE_DOMAINS = {'vr67rtyve56r4yerytv.shop'}

# Setup logging
logging.basicConfig(
    filename='/var/log/catchall/policy.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

def get_dns_config(domain):
    """Parse catchall-* TXT records from DNS"""
    config = {
        'forward': None,
        'limit': 50,
        'spam': 'moderate',
        'size': 5,
    }
    
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = str(rdata).strip('"')
            
            if txt.startswith('catchall-forward='):
                config['forward'] = txt.split('=', 1)[1]
            elif txt.startswith('catchall-limit='):
                try:
                    config['limit'] = int(txt.split('=', 1)[1])
                except:
                    pass
            elif txt.startswith('catchall-size='):
                try:
                    config['size'] = int(txt.split('=', 1)[1])
                except:
                    pass
    
    except Exception as e:
        logging.error(f"DNS lookup failed for {domain}: {e}")
        return None
    
    return config if config['forward'] else None

def check_rate_limit(domain, limit_per_day):
    """Check and enforce rate limits"""
    today = datetime.now().strftime('%Y-%m-%d')
    
    # Daily limit
    day_key = f"limit:{domain}:{today}"
    day_count = r.get(day_key)
    if day_count and int(day_count) >= limit_per_day:
        return False, "daily"
    
    # Minute limit (burst protection)
    min_key = f"limit:{domain}:minute"
    min_count = r.get(min_key)
    if min_count and int(min_count) >= 10:
        return False, "minute"
    
    # Increment both
    pipe = r.pipeline()
    pipe.incr(day_key)
    pipe.expire(day_key, 86400)
    pipe.incr(min_key)
    pipe.expire(min_key, 60)
    pipe.execute()

    return True, "ok"

def check_destination_limit(dest_domain):
    """
    Check per-destination rate limits to prevent flooding one provider.
    Returns: (ok: bool, reason: str)
    """
    today = datetime.now().strftime('%Y-%m-%d')
    hour = datetime.now().strftime('%Y-%m-%d-%H')

    # Daily limit per destination domain (e.g. gmail.com)
    dest_day_key = f"limit:dest:{dest_domain}:{today}"
    dest_day_count = r.get(dest_day_key)
    if dest_day_count and int(dest_day_count) >= DEST_DAILY_LIMIT:
        return False, f"Destination daily limit ({DEST_DAILY_LIMIT}) exceeded"

    # Hourly burst limit per destination
    dest_hour_key = f"limit:dest:{dest_domain}:hour:{hour}"
    dest_hour_count = r.get(dest_hour_key)
    if dest_hour_count and int(dest_hour_count) >= DEST_HOURLY_LIMIT:
        return False, f"Destination hourly limit ({DEST_HOURLY_LIMIT}) exceeded"

    # Increment counters
    pipe = r.pipeline()
    pipe.incr(dest_day_key)
    pipe.expire(dest_day_key, 86400)
    pipe.incr(dest_hour_key)
    pipe.expire(dest_hour_key, 3600)
    pipe.execute()

    return True, "ok"

async def handle_policy_request(reader, writer):
    """Handle Postfix policy protocol request"""
    request = {}
    
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            
            line = line.decode('utf-8').strip()
            if line == '':
                # End of request - process it
                response = await process_request(request)
                writer.write(response.encode('utf-8'))
                await writer.drain()
                request = {}
            else:
                if '=' in line:
                    key, value = line.split('=', 1)
                    request[key] = value
    
    except Exception as e:
        logging.error(f"Policy handler error: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

async def process_request(req):
    """Process policy request and return decision"""
    
    # Extract domain from recipient
    recipient = req.get('recipient', '')
    if not recipient or '@' not in recipient:
        return "action=DUNNO\n\n"
    
    domain = recipient.split('@')[1].lower()

    # Block disposable/abuse domains at SMTP time
    if domain in DISPOSABLE_DOMAINS or is_blocked_domain(domain):
        logging.warning(f"Blocked disposable domain: {domain}")
        return "action=550 5.1.1 Domain blocked due to abuse\n\n"

    # Get DNS configuration
    config = get_dns_config(domain)
    if not config:
        logging.info(f"No valid config for {domain}")
        return "action=550 5.1.1 Domain not configured for catchall\n\n"

    # Per-address rules from DNS: refuse blocked / unlisted addresses before
    # any content is accepted, and apply the abuse list to routed destinations
    try:
        rules = load_config(domain)
        if not rules.lookup_failed and rules.forward:
            action, target = resolve(rules, recipient.rsplit('@', 1)[0])
            if action == 'reject':
                logging.info(f"Address refused by {domain} rules ({target})")
                return "action=550 5.1.1 Address not accepted by this domain\n\n"
            if is_blocked_target(target):
                logging.warning(f"Blocked abusive routed target for {domain}")
                return "action=550 5.7.1 Domain blocked due to abuse\n\n"
    except Exception as e:
        logging.error(f"Rule check failed for {domain}: {e}")

    # Block abusive forward targets, whichever domain points at them
    if is_blocked_target(config['forward']):
        logging.warning(f"Blocked abusive forward target for {domain}: {config['forward']}")
        return "action=550 5.7.1 Domain blocked due to abuse\n\n"

    # Check rate limits (per source domain)
    rate_ok, limit_type = check_rate_limit(domain, config['limit'])
    if not rate_ok:
        if limit_type == "daily":
            logging.info(f"Daily limit exceeded for {domain}")
            return f"action=451 4.7.1 Daily limit ({config['limit']}) exceeded\n\n"
        else:
            logging.info(f"Minute limit exceeded for {domain}")
            return "action=451 4.7.1 Too many emails per minute\n\n"

    # Check destination rate limits (prevent one Gmail addr getting flooded)
    forward_to = config.get('forward', '')
    if forward_to and '@' in forward_to:
        dest_domain = forward_to.split('@')[1].lower()
        dest_ok, dest_reason = check_destination_limit(dest_domain)
        if not dest_ok:
            logging.warning(f"Destination limit for {dest_domain}: {dest_reason}")
            return f"action=451 4.7.1 {dest_reason}\n\n"

    # Check size
    size = int(req.get('size', 0))
    max_size_bytes = config['size'] * 1024 * 1024
    if size > max_size_bytes:
        logging.info(f"Email too large for {domain}: {size} bytes")
        return f"action=552 5.3.4 Message size exceeds limit ({config['size']}MB)\n\n"

    # Accept email - forwarder will handle verification
    logging.info(f"Accepting email for {domain}")

    return "action=DUNNO\n\n"

async def main():
    """Start policy daemon server"""
    logging.info("Starting policy daemon on port 10032")
    
    server = await asyncio.start_server(
        handle_policy_request,
        '127.0.0.1',
        POLICY_PORT
    )
    
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())
