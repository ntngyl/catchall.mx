#!/usr/bin/env python3
"""
CatchAll.mx Policy Daemon
Handles email routing decisions for Postfix
"""

import asyncio
import redis
import dns.resolver
import logging
import os
from datetime import datetime

# Load environment
from dotenv import load_dotenv
load_dotenv('/etc/catchall.env')

# Configuration
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
POLICY_PORT = 10032

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

    recipient = req.get('recipient', '')
    if not recipient or '@' not in recipient:
        return "action=DUNNO\n\n"

    domain = recipient.split('@')[1].lower()

    # Get DNS configuration
    config = get_dns_config(domain)
    if not config:
        logging.info(f"No valid config for {domain}")
        return "action=550 5.1.1 Domain not configured for catchall\n\n"

    # Check rate limits
    rate_ok, limit_type = check_rate_limit(domain, config['limit'])
    if not rate_ok:
        if limit_type == "daily":
            logging.info(f"Daily limit exceeded for {domain}")
            return f"action=451 4.7.1 Daily limit ({config['limit']}) exceeded\n\n"
        else:
            logging.info(f"Minute limit exceeded for {domain}")
            return "action=451 4.7.1 Too many emails per minute\n\n"

    # Check size
    size = int(req.get('size', 0))
    max_size_bytes = config['size'] * 1024 * 1024
    if size > max_size_bytes:
        logging.info(f"Email too large for {domain}: {size} bytes")
        return f"action=552 5.3.4 Message size exceeds limit ({config['size']}MB)\n\n"

    logging.info(f"Accepting email for {domain}")
    return "action=DUNNO\n\n"

async def main():
    """Start policy daemon server"""
    logging.info(f"Starting policy daemon on port {POLICY_PORT}")

    server = await asyncio.start_server(
        handle_policy_request,
        '127.0.0.1',
        POLICY_PORT
    )

    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())
