#!/usr/bin/env python3
"""
CatchAll.mx - Abuse blocklist
Blocks forward targets (and the domains pointed at them) that abuse the service.

Redis sets:
  abuse:targets  - normalized forward addresses that may not receive mail
  abuse:domains  - source domains that may not use the service

CLI: abuse.py block-target <email> | block-domain <domain> |
     unblock-target <email> | unblock-domain <domain> | list
"""

import redis

TARGETS_KEY = 'abuse:targets'
DOMAINS_KEY = 'abuse:domains'

r = redis.Redis(host='localhost', port=6379, decode_responses=True)

def normalize_target(address):
    """Canonical form of a forward address, so trivial variants can't dodge a block"""
    address = (address or '').strip().lower()
    if '@' not in address:
        return address
    local, domain = address.rsplit('@', 1)
    local = local.split('+', 1)[0]
    if domain in ('gmail.com', 'googlemail.com'):
        local = local.replace('.', '')
        domain = 'gmail.com'
    return f"{local}@{domain}"

def is_blocked_target(address):
    return bool(address) and r.sismember(TARGETS_KEY, normalize_target(address))

def is_blocked_domain(domain):
    return bool(domain) and r.sismember(DOMAINS_KEY, domain.strip().lower())

def is_abuse_blocked(domain, forward_to):
    return is_blocked_domain(domain) or is_blocked_target(forward_to)

if __name__ == '__main__':
    import sys

    args = sys.argv[1:]
    if args == ['list']:
        print("Blocked targets:", sorted(r.smembers(TARGETS_KEY)))
        print("Blocked domains:", sorted(r.smembers(DOMAINS_KEY)))
    elif len(args) == 2 and args[0] == 'block-target':
        r.sadd(TARGETS_KEY, normalize_target(args[1]))
    elif len(args) == 2 and args[0] == 'unblock-target':
        r.srem(TARGETS_KEY, normalize_target(args[1]))
    elif len(args) == 2 and args[0] == 'block-domain':
        r.sadd(DOMAINS_KEY, args[1].strip().lower())
    elif len(args) == 2 and args[0] == 'unblock-domain':
        r.srem(DOMAINS_KEY, args[1].strip().lower())
    else:
        print(__doc__)
        sys.exit(1)
