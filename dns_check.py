#!/usr/bin/env python3
"""
CatchAll.mx - DNS setup checker

Looks at a domain's DNS the same way the forwarder does and names the specific
mistake, so the website can tell the user exactly what to change.
"""
import re
import time

import dns.exception
import dns.resolver
import redis

MX_TARGET = 'mail.catchall.mx'
DOMAIN_RE = re.compile(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}')
EMAIL_RE = re.compile(r'[^@\s"<>,;]+@((?:[a-z0-9-]+\.)+[a-z0-9-]{2,63})', re.I)

r = redis.Redis(decode_responses=True)


def clean_domain(raw):
    """Accept what people actually paste: URLs, email addresses, trailing dots."""
    d = (raw or '').strip().lower()
    d = re.sub(r'^[a-z]+://', '', d)
    d = d.split('/')[0].split('?')[0]
    if '@' in d:
        d = d.rsplit('@', 1)[1]
    d = d.split(':')[0].strip('.').strip()
    if d.startswith('www.') and d.count('.') >= 2:
        d = d[4:]
    return d


def _resolver():
    res = dns.resolver.Resolver()
    res.lifetime = 6
    return res


def _txt_values(res, name):
    """All TXT values at name; multi-string records are joined like verifiers do."""
    out = []
    for rdata in res.resolve(name, 'TXT'):
        out.append(b''.join(rdata.strings).decode('utf-8', 'replace'))
    return out


def _issue(issues, level, text, fix=None):
    item = {'level': level, 'text': text}
    if fix:
        item['fix'] = fix
    issues.append(item)


def _check_mx(res, domain, result, issues):
    try:
        answers = sorted(res.resolve(domain, 'MX'), key=lambda m: m.preference)
    except dns.resolver.NXDOMAIN:
        result['mx_record'] = {'found': False, 'error': 'Domain not found'}
        _issue(issues, 'error',
               f"{domain} does not exist in DNS. Check the spelling, or the domain may be "
               "unregistered or expired.")
        return False
    except dns.resolver.NoAnswer:
        result['mx_record'] = {'found': False, 'error': 'No MX record found'}
        _issue(issues, 'error', "No MX record found.",
               f"Add an MX record: host @ (or {domain}), value {MX_TARGET}, priority 10.")
        return True
    except dns.exception.DNSException:
        result['mx_record'] = {'found': False, 'error': 'DNS lookup failed'}
        _issue(issues, 'error',
               "Your domain's name servers did not answer. Check that the domain's name servers "
               "are set correctly at your registrar, then try again in a few minutes.")
        return False

    hosts = [(m.preference, str(m.exchange).rstrip('.').lower()) for m in answers]
    if all(h[1] == '' for h in hosts):
        # "Null MX" (RFC 7505): the domain announces that it accepts no mail
        result['mx_record'] = {'found': False, 'error': 'Null MX'}
        _issue(issues, 'error', "Your domain has a \"null MX\" record, which tells senders it accepts no email.",
               f"Replace it with an MX record: value {MX_TARGET}, priority 10.")
        return True
    hosts = [h for h in hosts if h[1]]
    ours = [h for h in hosts if h[1] == MX_TARGET]
    others = [h for h in hosts if h[1] != MX_TARGET]

    if ours:
        result['mx_record'] = {'found': True, 'value': MX_TARGET,
                               'priority': ours[0][0], 'valid': True}
        if others:
            names = ', '.join(h[1] for h in others)
            _issue(issues, 'warning',
                   f"Other MX records are also present ({names}). Some mail will be delivered "
                   "there instead of being forwarded.",
                   f"Remove the other MX records so {MX_TARGET} is the only one.")
        return True

    result['mx_record'] = {'found': False, 'error': 'MX does not point to mail.catchall.mx',
                           'current': [h[1] for h in hosts]}
    for _, host in hosts:
        if host.startswith(MX_TARGET + '.'):
            _issue(issues, 'error',
                   f"Your MX points to {host}. Your DNS provider added your own domain to the end "
                   "of the value.",
                   f"Enter the value with a trailing dot ({MX_TARGET}.) or pick the provider's "
                   "\"fully qualified\" option.")
            return True
    for _, host in hosts:
        if host in ('catchall.mx', 'www.catchall.mx', 'mx.catchall.mx', 'smtp.catchall.mx') \
                or host.endswith('.catchall.mx'):
            _issue(issues, 'error', f"Your MX points to {host}, which is not our mail server.",
                   f"Change the MX value to exactly {MX_TARGET}.")
            return True
    for _, host in hosts:
        if re.fullmatch(r'[0-9.]+', host):
            _issue(issues, 'error', f"Your MX value is an IP address ({host}). MX records need a name.",
                   f"Change the MX value to {MX_TARGET}.")
            return True
    names = ', '.join(h[1] for h in hosts[:2]) or 'nothing'
    if len(hosts) > 2:
        names += f" and {len(hosts) - 2} more"
    _issue(issues, 'error', f"Your MX currently points to {names}, so mail goes there, not to us.",
           f"Replace it with one MX record: value {MX_TARGET}, priority 10.")
    return True


def _check_forward(res, domain, result, issues):
    try:
        values = _txt_values(res, domain)
    except dns.exception.DNSException:
        values = []

    forward = None
    near_miss = None
    count = 0
    for txt in values:
        if 'catchall-forward=' in txt:
            count += 1
            if forward is None:
                forward = txt
        elif re.search(r'catch[\s_-]*all[\s_-]*forward', txt, re.I):
            near_miss = txt

    limit = next((t.split('=', 1)[1].strip() for t in values if t.startswith('catchall-limit=')), None)
    spam = next((t.split('=', 1)[1].strip() for t in values if t.startswith('catchall-spam=')), None)
    result['txt_records']['catchall-limit'] = (
        {'found': True, 'value': limit, 'valid': limit.isdigit()} if limit is not None
        else {'found': False, 'default': '50'})
    result['txt_records']['catchall-spam'] = (
        {'found': True, 'value': spam, 'valid': spam in ('strict', 'moderate', 'off')} if spam is not None
        else {'found': False, 'default': 'moderate'})
    if limit is not None and not limit.isdigit():
        _issue(issues, 'warning', f"catchall-limit=\"{limit}\" is not a number, so the default of 50 is used.")
    if spam is not None and spam not in ('strict', 'moderate', 'off'):
        _issue(issues, 'warning', f"catchall-spam=\"{spam}\" is not valid. Use strict, moderate or off.")

    if forward is None:
        if near_miss:
            _issue(issues, 'error',
                   f"Found a TXT record that looks like a forward record but is not written correctly: "
                   f"\"{near_miss[:80]}\".",
                   "It must be exactly catchall-forward=you@example.com: lowercase, a hyphen, "
                   "an equals sign and no spaces.")
        else:
            # A common mistake: the record was created on a sub-name instead of the domain itself
            for sub in ('catchall-forward', '_catchall', 'mail', 'www'):
                try:
                    if any('catchall-forward=' in t for t in _txt_values(res, f"{sub}.{domain}")):
                        _issue(issues, 'error',
                               f"The forward record is on {sub}.{domain} instead of {domain}.",
                               "Move the TXT record to the domain itself: host @ (or leave the "
                               "host field empty).")
                        break
                except dns.exception.DNSException:
                    continue
            else:
                _issue(issues, 'error', "No forward record found.",
                       "Add a TXT record: host @, value catchall-forward=you@example.com")
        return None

    raw_value = forward.split('catchall-forward=', 1)[1]
    value = raw_value.split()[0] if raw_value.split() else ''
    entry = {'found': True, 'value': value, 'valid': False}
    result['txt_records']['catchall-forward'] = entry

    if count > 1:
        _issue(issues, 'warning',
               f"There are {count} catchall-forward records. Only one is used ({value}).",
               "Delete the extra records.")
    if '"' in forward or "'" in forward:
        _issue(issues, 'error', "The forward record contains quote characters.",
               "Edit the TXT record and remove the quotes around the value.")
        return None
    if not forward.startswith('catchall-forward='):
        _issue(issues, 'warning',
               "The forward record has extra text before \"catchall-forward=\". It works, but "
               "keep the record to just catchall-forward=you@example.com.")
    if value.lower().startswith('mailto:'):
        _issue(issues, 'error', "The forward address starts with \"mailto:\".",
               "Use only the address: catchall-forward=you@example.com")
        return None
    m = EMAIL_RE.fullmatch(value)
    if not m:
        _issue(issues, 'error', f"\"{value[:80]}\" is not a valid email address.",
               "Use one address, for example catchall-forward=you@example.com")
        return None
    target_domain = m.group(1).lower()
    if target_domain == domain or target_domain.endswith('.' + domain):
        _issue(issues, 'error',
               f"The forward address is on {target_domain} itself, so mail would loop back to us.",
               "Forward to a mailbox on another domain (Gmail, Outlook, etc.).")
        return None
    try:
        res.resolve(target_domain, 'MX')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        _issue(issues, 'error',
               f"The forward address domain ({target_domain}) cannot receive email. "
               "Check the address for a typo.")
        return None
    except dns.exception.DNSException:
        pass
    entry['valid'] = True
    return value


def check_domain(raw_domain, is_dkim_enabled=None, is_abuse_blocked=None):
    """Full check. Returns the dict served by /api/check-dns."""
    domain = clean_domain(raw_domain)
    result = {
        'domain': domain,
        'mx_record': {'found': False},
        'txt_records': {},
        'dkim': {'enabled': False},
        'verified': False,
        'issues': [],
        'status': 'incomplete',
    }
    issues = result['issues']

    if not domain or len(domain) > 253 or not DOMAIN_RE.fullmatch(domain):
        result['message'] = 'That does not look like a domain name.'
        _issue(issues, 'error', "Enter just the domain, for example example.com "
                                "(no http://, no email address).")
        return result
    if domain == 'catchall.mx' or domain.endswith('.catchall.mx'):
        result['message'] = 'Enter your own domain, not catchall.mx.'
        _issue(issues, 'error', "Enter the domain you want to receive mail for.")
        return result

    res = _resolver()
    exists = _check_mx(res, domain, result, issues)
    forward_to = _check_forward(res, domain, result, issues) if exists else None

    # Optional per-address rules (routing.py reads them the same way)
    if exists:
        try:
            from routing import parse_txt
            cfg = parse_txt(_txt_values(res, domain))
            result['rules'] = {
                'routes': [{'address': f"{n}@{domain}", 'to': t} for n, t in cfg.routes],
                'block': [f"{n}@{domain}" for n in cfg.block],
                'only': [f"{n}@{domain}" for n in cfg.only],
            }
            for err in cfg.errors:
                _issue(issues, 'warning', err)
            for name, target in cfg.routes:
                tdom = target.rsplit('@', 1)[1].lower()
                if tdom == domain or tdom.endswith('.' + domain):
                    _issue(issues, 'error',
                           f"The route for {name}@{domain} points to an address on {tdom} itself, "
                           "so that mail would loop back to us.",
                           "Route it to a mailbox on another domain.")
            if cfg.only and forward_to:
                _issue(issues, 'info',
                       f"Allow-list is on: only {len(cfg.only) + len(cfg.routes)} listed address(es) "
                       "accept mail. Mail to any other address is refused.")
        except dns.exception.DNSException:
            pass

    # Raw current records, for the record builder on the website (/setup/)
    current = {'mx': [], 'txt': [], 'config': None}
    if exists:
        try:
            current['mx'] = [{'priority': m.preference, 'host': str(m.exchange).rstrip('.').lower()}
                             for m in sorted(res.resolve(domain, 'MX'), key=lambda m: m.preference)]
        except dns.exception.DNSException:
            pass
        try:
            values = _txt_values(res, domain)
            current['txt'] = [v for v in values if re.match(r'\s*catch[\s_-]*all', v, re.I)
                              or 'catchall-forward=' in v]
            from routing import parse_txt
            cfg = parse_txt(values)
            opt = {}
            for v in values:
                m = re.fullmatch(r'catchall-(limit|spam|size)=(\S+)', v.strip())
                if m:
                    opt[m.group(1)] = m.group(2)
            current['config'] = {
                'forward': cfg.forward, 'routes': [[n, t] for n, t in cfg.routes],
                'block': cfg.block, 'only': cfg.only,
                'limit': opt.get('limit'), 'spam': opt.get('spam'), 'size': opt.get('size'),
            }
        except dns.exception.DNSException:
            pass
    # Name servers tell the builder which DNS provider's instructions to show.
    # A subdomain usually has no NS of its own, so walk up to the parent.
    current['nameservers'] = []
    if exists:
        name = domain
        for _ in range(4):
            try:
                current['nameservers'] = sorted(str(n.target).rstrip('.').lower()
                                                for n in res.resolve(name, 'NS'))
                break
            except dns.exception.DNSException:
                if name.count('.') < 2:
                    break
                name = name.split('.', 1)[1]
    result['current'] = current

    if is_dkim_enabled:
        try:
            result['dkim']['enabled'] = bool(is_dkim_enabled(domain))
        except Exception:
            pass

    mx_ok = result['mx_record'].get('valid', False)
    forward_ok = forward_to is not None

    if mx_ok and forward_ok and is_abuse_blocked:
        try:
            if is_abuse_blocked(domain, forward_to):
                result['status'] = 'blocked'
                result['message'] = 'This domain or forward address is blocked.'
                _issue(issues, 'error',
                       "Forwarding is disabled for this domain or forward address because of "
                       "abuse. Contact us if you think this is a mistake.")
                return result
        except Exception:
            pass

    if mx_ok and forward_ok:
        result['status'] = 'ready'
        result['message'] = 'Your domain is configured correctly!'
        if result['dkim']['enabled']:
            result['message'] += ' DKIM signing is enabled.'
        try:
            ts = r.get(f"active:{domain}")
            result['verified'] = bool(ts) and (time.time() - int(ts)) < 30 * 86400
        except Exception:
            pass
        if not result['verified']:
            _issue(issues, 'info',
                   f"One step left: send an email to any address at {domain}. We will send a "
                   f"confirmation link to {forward_to} (check the spam folder). Forwarding "
                   "starts once you click it.")
    elif forward_ok:
        result['status'] = 'partial'
        result['message'] = 'Forward record is fine. The MX record needs fixing.'
    elif mx_ok:
        result['status'] = 'partial'
        result['message'] = 'MX record is fine. The forward record needs fixing.'
    else:
        result['message'] = 'DNS records are not configured yet.'

    return result


if __name__ == '__main__':
    import json
    import sys
    print(json.dumps(check_domain(sys.argv[1]), indent=2))
