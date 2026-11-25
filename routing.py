#!/usr/bin/env python3
"""
CatchAll.mx - per-address rules, configured only in the user's DNS

TXT records on the domain itself (nothing is stored on our side):

  catchall-forward=you@example.com            default destination (required)
  catchall-route=billing:accounts@example.com send one address elsewhere
  catchall-block=oldshop,news-*               refuse these addresses
  catchall-only=info,sales,me                 refuse everything except these

Several rules can share one record (comma separated) or use separate records.
Address names are the part before the @, case-insensitive; * is a wildcard and
a +tag is ignored (info+x matches info). Order: block, then only, then route,
then the default forward.

Consent: a destination only receives mail after its owner clicked the
confirmation link. We keep one salted hash per confirmed (domain, destination)
pair in Redis set consent:<domain>, never the address itself.
"""
import fnmatch
import hashlib
import re

import dns.exception
import dns.resolver
import redis

MAX_ROUTES = 25
MAX_PATTERNS = 100
LOCAL_RE = re.compile(r'[a-z0-9._*+-]{1,64}')
EMAIL_RE = re.compile(r'[^@\s"<>,;:]+@(?:[a-z0-9-]+\.)+[a-z0-9-]{2,63}', re.I)

r = redis.Redis(host='localhost', port=6379, decode_responses=True)


class Config:
    def __init__(self):
        self.forward = None
        self.routes = []      # [(pattern, target)]
        self.block = []       # [pattern]
        self.only = []        # [pattern]
        self.errors = []      # human-readable problems, for the DNS checker
        self.lookup_failed = False

    def targets(self):
        """Every destination this domain can forward to."""
        seen = []
        for t in [self.forward] + [t for _, t in self.routes]:
            if t and t.lower() not in [s.lower() for s in seen]:
                seen.append(t)
        return seen


def _items(value):
    return [v.strip() for v in re.split(r'[,;\s]+', value) if v.strip()]


def parse_txt(values):
    """Build a Config from the TXT values of a domain."""
    cfg = Config()
    for txt in values:
        txt = txt.strip()
        if 'catchall-forward=' in txt and cfg.forward is None:
            parts = txt.split('catchall-forward=', 1)[1].split()
            cfg.forward = parts[0] if parts else None
        elif txt.startswith('catchall-route='):
            for item in _items(txt.split('=', 1)[1]):
                name, sep, target = item.partition(':')
                name = name.lower().split('@')[0]
                if not sep or not LOCAL_RE.fullmatch(name) or not EMAIL_RE.fullmatch(target):
                    cfg.errors.append(f"catchall-route entry \"{item[:60]}\" is not valid. "
                                      "Use name:destination, for example billing:accounts@example.com")
                elif len(cfg.routes) >= MAX_ROUTES:
                    cfg.errors.append(f"Only the first {MAX_ROUTES} catchall-route entries are used.")
                    break
                else:
                    cfg.routes.append((name, target))
        elif txt.startswith('catchall-block=') or txt.startswith('catchall-only='):
            key = 'block' if txt.startswith('catchall-block=') else 'only'
            dest = cfg.block if key == 'block' else cfg.only
            for item in _items(txt.split('=', 1)[1]):
                name = item.lower().split('@')[0]
                if not LOCAL_RE.fullmatch(name):
                    cfg.errors.append(f"catchall-{key} entry \"{item[:60]}\" is not valid. Use only the "
                                      "part before the @, for example info or news-*")
                elif len(dest) < MAX_PATTERNS:
                    dest.append(name)
    return cfg


def load_config(domain):
    """Read the domain's rules from DNS. cfg.lookup_failed is set on DNS errors."""
    try:
        res = dns.resolver.Resolver()
        res.lifetime = 8
        values = [b''.join(rd.strings).decode('utf-8', 'replace')
                  for rd in res.resolve(domain, 'TXT')]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return Config()
    except dns.exception.DNSException:
        cfg = Config()
        cfg.lookup_failed = True
        return cfg
    return parse_txt(values)


def _matches(local, patterns):
    local = local.lower()
    base = local.split('+', 1)[0]
    for p in patterns:
        if fnmatch.fnmatchcase(local, p) or fnmatch.fnmatchcase(base, p):
            return p
    return None


def resolve(cfg, local):
    """
    Decide what happens to mail for <local>@domain.
    Returns ('reject', reason) or ('forward', destination).
    """
    if _matches(local, cfg.block):
        return 'reject', 'blocked'
    route_names = [n for n, _ in cfg.routes]
    hit = _matches(local, route_names)
    if cfg.only and not _matches(local, cfg.only) and not hit:
        return 'reject', 'not-listed'
    if hit:
        return 'forward', dict(cfg.routes)[hit]
    if cfg.forward:
        return 'forward', cfg.forward
    return 'reject', 'no-forward'


# --- consent ---------------------------------------------------------------

def _norm(target):
    return (target or '').strip().lower()


def consent_hash(domain, target):
    return hashlib.sha256(f"catchall-consent|{domain.lower()}|{_norm(target)}".encode()).hexdigest()


def queue_name(domain, target, default_target):
    """Queue/verification key: the bare domain for the default destination,
    domain~<short hash> for a routed destination."""
    if _norm(target) == _norm(default_target):
        return domain
    return f"{domain}~{consent_hash(domain, target)[:12]}"


def split_queue_name(name):
    """Return (domain, short_hash or None)."""
    domain, _, short = name.partition('~')
    return domain, (short or None)


def target_for_queue(name, cfg):
    """Destination a queue belongs to, or None if it is no longer configured."""
    domain, short = split_queue_name(name)
    if short is None:
        return cfg.forward
    for t in cfg.targets():
        if consent_hash(domain, t)[:12] == short:
            return t
    return None


def grant_consent(domain, target):
    r.sadd(f"consent:{domain}", consent_hash(domain, target))


def revoke_all_consent(domain):
    r.delete(f"consent:{domain}")


def has_consent(domain, target, default_target=None):
    """
    True if this destination confirmed forwarding from this domain.
    Domains verified before consent tracking existed are grandfathered once:
    their current default destination is taken as the confirmed one.
    """
    key = f"consent:{domain}"
    if default_target and not r.exists(key) and r.exists(f"active:{domain}"):
        grant_consent(domain, default_target)
    return bool(r.sismember(key, consent_hash(domain, target)))
