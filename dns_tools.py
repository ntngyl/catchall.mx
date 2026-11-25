#!/usr/bin/env python3
"""
CatchAll.mx - free DNS tools

MX, SPF, DKIM and DMARC lookups for any domain. Reads public DNS only and
stores nothing. Every function returns the same shape so the website can
render all four tools with one piece of code:

    {tool, domain, summary: {level, text}, records: [{label, value}],
     details: [[name, meaning], ...], notes: [{level, text, fix?}]}

Levels are success / warning / error / info.
"""
import base64
import re
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

from dns_check import clean_domain, DOMAIN_RE

MAX_SPF_FETCHES = 20          # hard stop on DNS work for one SPF check
SELECTOR_RE = re.compile(r'[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?', re.I)

# Selectors the well-known mail services use. DNS cannot list selectors, so
# without one from the user these are the only ones that can be tried.
COMMON_SELECTORS = [
    'google', 'selector1', 'selector2', 'default', 'catchall', 'rs1', 'k1', 'k2', 'k3',
    's1', 's2', 'mail', 'dkim', 'smtp', 'key1', 'sig1', 'pm', 'fm1', 'fm2', 'fm3',
    'protonmail', 'protonmail2', 'protonmail3', 'zoho', 'zmail', 'mandrill',
    'mailjet', 'krs', 'mte1', 'mxvault', 'cf2024-1',
]

MAIL_SERVICES = [
    (r'(^|\.)mail\.catchall\.mx$', 'catchall.mx'),
    (r'(google|googlemail)\.com$', 'Google Workspace / Gmail'),
    (r'\.outlook\.com$', 'Microsoft 365'),
    (r'mx\.cloudflare\.net$', 'Cloudflare Email Routing'),
    (r'improvmx\.com$', 'ImprovMX'),
    (r'forwardemail\.net$', 'Forward Email'),
    (r'zoho\.(com|eu|in)$', 'Zoho Mail'),
    (r'protonmail\.ch$', 'Proton Mail'),
    (r'messagingengine\.com$', 'Fastmail'),
    (r'icloud\.com$', 'iCloud Mail'),
    (r'secureserver\.net$', 'GoDaddy email'),
    (r'(privateemail\.com|registrar-servers\.com)$', 'Namecheap email'),
    (r'titan\.email$', 'Titan'),
    (r'yandex\.(net|ru)$', 'Yandex Mail'),
    (r'mailgun\.org$', 'Mailgun'),
    (r'(pphosted\.com|ppe-hosted\.com)$', 'Proofpoint'),
    (r'mimecast\.com$', 'Mimecast'),
    (r'(ionos|kundenserver|1and1)\.[a-z.]+$', 'IONOS'),
    (r'hostinger\.com$', 'Hostinger email'),
    (r'ovh\.net$', 'OVHcloud'),
    (r'gandi\.net$', 'Gandi'),
    (r'migadu\.com$', 'Migadu'),
    (r'simplelogin\.co$', 'SimpleLogin'),
    (r'amazonaws\.com$', 'Amazon SES / WorkMail'),
]


def _resolver():
    res = dns.resolver.Resolver()
    res.lifetime = 5
    return res


def _txt(res, name):
    """(values, status) where status is ok / nxdomain / empty / error."""
    try:
        return ([b''.join(rd.strings).decode('utf-8', 'replace')
                 for rd in res.resolve(name, 'TXT')], 'ok')
    except dns.resolver.NXDOMAIN:
        return [], 'nxdomain'
    except dns.resolver.NoAnswer:
        return [], 'empty'
    except dns.exception.DNSException:
        return [], 'error'


def _note(notes, level, text, fix=None):
    n = {'level': level, 'text': text}
    if fix:
        n['fix'] = fix
    notes.append(n)


def _result(tool, domain):
    return {'tool': tool, 'domain': domain, 'summary': None,
            'records': [], 'details': [], 'notes': []}


def _summarise(out, good, missing=None):
    """Worst note level decides the headline."""
    levels = {n['level'] for n in out['notes']}
    if missing:
        out['summary'] = {'level': 'error', 'text': missing}
    elif 'error' in levels:
        out['summary'] = {'level': 'error', 'text': 'Found, but it has a problem that needs fixing.'}
    elif 'warning' in levels:
        out['summary'] = {'level': 'warning', 'text': 'Found and working, with something worth a look.'}
    else:
        out['summary'] = {'level': 'success', 'text': good}
    return out


def _lookup_failed(out):
    out['summary'] = {'level': 'error',
                      'text': 'The DNS lookup failed. The domain\'s nameservers did not answer; try again in a minute.'}
    return out


def _service(host):
    for pattern, name in MAIL_SERVICES:
        if re.search(pattern, host):
            return name
    return None


# ---------------------------------------------------------------- MX

def mx_lookup(domain, res=None):
    res = res or _resolver()
    out = _result('mx', domain)
    notes = out['notes']
    try:
        answers = sorted(res.resolve(domain, 'MX'), key=lambda m: (m.preference, str(m.exchange)))
    except dns.resolver.NXDOMAIN:
        return _summarise(out, '', f'{domain} does not exist in DNS. Check the spelling.')
    except dns.resolver.NoAnswer:
        _note(notes, 'error', 'No MX records.',
              'Without an MX record, mail servers fall back to the domain\'s website address, '
              'which almost never accepts mail. Add an MX record for the mail service you use.')
        return _summarise(out, '', 'This domain has no MX records, so it cannot reliably receive email.')
    except dns.exception.DNSException:
        return _lookup_failed(out)

    hosts = [(m.preference, str(m.exchange).rstrip('.').lower()) for m in answers]
    if len(hosts) == 1 and hosts[0][1] == '':
        _note(notes, 'warning', 'This is a "null MX" record (priority 0, target ".").',
              'It tells the world this domain accepts no email at all. Remove it if you want to receive mail.')
        out['records'].append({'label': 'MX', 'value': '0 .'})
        return _summarise(out, '')

    services = []
    for prio, host in hosts[:8]:
        out['records'].append({'label': 'MX', 'value': f'{prio} {host}'})
        service = _service(host)
        if service and service not in services:
            services.append(service)
        addresses, problem = [], None
        if re.fullmatch(r'[0-9.]+', host):
            problem = 'is an IP address. An MX record must name a host, not an address.'
        else:
            try:
                addresses = [a.address for a in res.resolve(host, 'A')][:4]
            except dns.resolver.NXDOMAIN:
                problem = 'does not exist in DNS, so mail sent to it fails.'
            except dns.resolver.NoAnswer:
                try:
                    addresses = [a.address for a in res.resolve(host, 'AAAA')][:2]
                except dns.exception.DNSException:
                    pass
                if not addresses:
                    problem = 'has no IP address, so mail sent to it fails.'
            except dns.exception.DNSException:
                pass
        meaning = (service or 'Mail server') + (' at ' + ', '.join(addresses) if addresses else '')
        out['details'].append([f'{prio} {host}', meaning])
        if problem:
            _note(notes, 'error', f'{host} {problem}')

    if len(services) > 1:
        _note(notes, 'warning',
              'The MX records point at more than one mail service: ' + ', '.join(services) + '.',
              'Sending servers pick by priority and fall back to the others, so mail ends up split '
              'between services. Keep the records of one service and delete the rest.')
    if len(hosts) == 1:
        _note(notes, 'info', 'One MX record. That is fine: sending servers retry for days if it is briefly down.')
    else:
        _note(notes, 'info', f'{len(hosts)} MX records. The lowest number is tried first.')
    good = 'Mail for this domain goes to ' + (services[0] if len(services) == 1 else hosts[0][1]) + '.'
    return _summarise(out, good)


# ---------------------------------------------------------------- SPF

SPF_MEANING = {
    'all': 'every other sender',
    'a': "the domain's own address (A record)",
    'mx': "the domain's own mail servers (MX records)",
    'ptr': 'senders whose reverse DNS matches (deprecated)',
}
QUALIFIER = {'+': 'Allow', '-': 'Reject', '~': 'Mark as suspicious', '?': 'No opinion on'}


def _spf_records(values):
    return [v.strip() for v in values if re.match(r'v=spf1(\s|$)', v.strip(), re.I)]


def _spf_walk(res, domain, state, depth=0):
    """Count the DNS lookups an SPF record costs, following include and redirect."""
    if depth > 10 or state['fetches'] >= MAX_SPF_FETCHES or domain in state['seen']:
        if domain in state['seen'] and depth:
            state['loops'].add(domain)
        return
    state['seen'].add(domain)
    state['fetches'] += 1
    values, status = _txt(res, domain)
    records = _spf_records(values)
    if not records:
        if depth:
            state['broken'].append(domain)
        return
    for term in records[0].split()[1:]:
        t = term.lower().lstrip('+-~?')
        if t.startswith('include:'):
            state['lookups'] += 1
            _spf_walk(res, t[8:].strip('.'), state, depth + 1)
        elif t.startswith('redirect='):
            state['lookups'] += 1
            _spf_walk(res, t[9:].strip('.'), state, depth + 1)
        elif t.startswith(('exists:', 'ptr')) or t == 'a' or t.startswith(('a:', 'a/')) \
                or t == 'mx' or t.startswith(('mx:', 'mx/')):
            state['lookups'] += 1


def spf_check(domain, res=None):
    res = res or _resolver()
    out = _result('spf', domain)
    notes = out['notes']
    values, status = _txt(res, domain)
    if status == 'nxdomain':
        return _summarise(out, '', f'{domain} does not exist in DNS. Check the spelling.')
    if status == 'error':
        return _lookup_failed(out)
    records = _spf_records(values)
    if not records:
        _note(notes, 'error', 'No SPF record.',
              'Add one TXT record on the domain itself that starts with v=spf1 and lists the services '
              'that send mail as this domain. If the domain sends no mail at all, use: v=spf1 -all')
        return _summarise(out, '', 'This domain has no SPF record.')
    for rec in records:
        out['records'].append({'label': 'TXT', 'value': rec})
    if len(records) > 1:
        _note(notes, 'error', f'{len(records)} SPF records found. A domain may have only one.',
              'Receivers treat more than one as a permanent error and ignore all of them. '
              'Merge them into a single record: one v=spf1, all the include: parts, one "all" at the end.')

    record = records[0]
    terms = record.split()[1:]
    has_all = has_redirect = False
    for i, term in enumerate(terms):
        q = term[0] if term[0] in QUALIFIER else '+'
        body = term.lstrip('+-~?')
        low = body.lower()
        action = QUALIFIER[q]
        if low == 'all':
            has_all = True
            out['details'].append([term, f'{action} {SPF_MEANING["all"]}'])
            if i != len(terms) - 1:
                _note(notes, 'warning', f'"{term}" is not the last part of the record.',
                      'Everything after "all" is ignored. Move it to the end.')
            if q == '+':
                _note(notes, 'error', '"+all" allows every server on the internet to send as this domain.',
                      'Change it to ~all or -all.')
            elif q == '?':
                _note(notes, 'warning', '"?all" gives no opinion on unlisted senders, so the record protects nothing.',
                      'Change it to ~all, or -all once you are sure every sender is listed.')
        elif low.startswith('include:'):
            out['details'].append([term, f'{action} whatever {body[8:]} allows'])
        elif low.startswith('redirect='):
            has_redirect = True
            out['details'].append([term, f'Use the SPF record of {body[9:]} instead'])
        elif low.startswith('ip4:') or low.startswith('ip6:'):
            out['details'].append([term, f'{action} the address {body[4:]}'])
        elif low.startswith('exists:'):
            out['details'].append([term, f'{action} senders for which {body[7:]} resolves'])
        elif low.startswith('exp='):
            out['details'].append([term, 'Explanation shown when mail is rejected'])
        elif low.split(':')[0].split('/')[0] in ('a', 'mx', 'ptr'):
            kind = low.split(':')[0].split('/')[0]
            other = body.split(':', 1)[1] if ':' in body else None
            meaning = SPF_MEANING[kind] if not other else SPF_MEANING[kind].replace("the domain's own", f"{other}'s")
            out['details'].append([term, f'{action} {meaning}'])
            if kind == 'ptr':
                _note(notes, 'warning', 'The "ptr" mechanism is deprecated and slow; some receivers ignore it.',
                      'Replace it with ip4:, ip6: or include: entries.')
        else:
            out['details'].append([term, 'Not a valid SPF term'])
            _note(notes, 'error', f'"{term}" is not valid SPF.',
                  'An unknown term makes the whole record a permanent error. Remove or correct it.')

    if not has_all and not has_redirect:
        _note(notes, 'warning', 'The record does not end with an "all" term.',
              'Without it, unlisted senders get a neutral result. Add ~all or -all at the end.')

    state = {'lookups': 0, 'fetches': 0, 'seen': set(), 'loops': set(), 'broken': []}
    _spf_walk(res, domain, state)
    out['details'].append(['DNS lookups', f'{state["lookups"]} of the 10 allowed'
                           + (' (stopped counting)' if state['fetches'] >= MAX_SPF_FETCHES else '')])
    if state['lookups'] > 10:
        _note(notes, 'error', f'The record needs {state["lookups"]} DNS lookups; the limit is 10.',
              'Past 10, receivers return a permanent error and SPF fails for all your mail. '
              'Remove include: entries for services you no longer send from.')
    elif state['lookups'] >= 8:
        _note(notes, 'warning', f'The record uses {state["lookups"]} of 10 allowed DNS lookups.',
              'One more service could push it over the limit.')
    for broken in state['broken'][:3]:
        _note(notes, 'warning', f'{broken} is included but has no SPF record of its own.',
              'Remove that include: entry, or check its spelling.')
    if len(record) > 450:
        _note(notes, 'warning', f'The record is {len(record)} characters long.',
              'Very long SPF records can fail to fit in a DNS reply. Trim what you do not need.')
    return _summarise(out, 'This domain has a valid SPF record.')


# ---------------------------------------------------------------- DMARC

DMARC_POLICY = {
    'none': 'Take no action; only send reports',
    'quarantine': 'Put failing mail in the spam folder',
    'reject': 'Refuse failing mail outright',
}


def _dmarc_at(res, name):
    values, status = _txt(res, '_dmarc.' + name)
    return [v.strip() for v in values if re.match(r'v\s*=\s*DMARC1\s*(;|$)', v.strip(), re.I)], status


def dmarc_check(domain, res=None):
    res = res or _resolver()
    out = _result('dmarc', domain)
    notes = out['notes']
    records, status = _dmarc_at(res, domain)
    if status == 'error':
        return _lookup_failed(out)
    found_at = domain
    labels = domain.split('.')
    while not records and len(labels) > 2:          # fall back towards the organisational domain
        labels = labels[1:]
        found_at = '.'.join(labels)
        records, _ = _dmarc_at(res, found_at)
    if not records:
        _note(notes, 'error', 'No DMARC record.',
              f'Add a TXT record at _dmarc.{domain}. A safe first value that changes nothing and only '
              f'sends you reports: v=DMARC1; p=none; rua=mailto:you@{domain}')
        return _summarise(out, '', 'This domain has no DMARC record.')
    for rec in records:
        out['records'].append({'label': f'_dmarc.{found_at}', 'value': rec})
    inherited = found_at != domain
    if inherited:
        _note(notes, 'info', f'{domain} has no DMARC record of its own, so the one on {found_at} applies.')
    if len(records) > 1:
        _note(notes, 'error', f'{len(records)} DMARC records found. Only one is allowed.',
              'Receivers ignore DMARC completely when there is more than one. Delete the extras.')

    tags = {}
    for part in records[0].split(';'):
        if '=' in part:
            k, v = part.split('=', 1)
            tags[k.strip().lower()] = v.strip()
    policy = tags.get('p', '').lower()
    effective = (tags.get('sp', '').lower() or policy) if inherited else policy
    if policy not in DMARC_POLICY:
        out['details'].append(['p=' + tags.get('p', ''), 'Missing or not a valid policy'])
        _note(notes, 'error', 'The record has no valid p= policy.',
              'p must be none, quarantine or reject. Without it the record is ignored.')
    else:
        out['details'].append(['p=' + policy, DMARC_POLICY[policy]])
    if 'sp' in tags:
        out['details'].append(['sp=' + tags['sp'], 'Policy for subdomains: '
                               + DMARC_POLICY.get(tags['sp'].lower(), 'not valid').lower()])
    if 'pct' in tags:
        out['details'].append(['pct=' + tags['pct'], f'Apply the policy to {tags["pct"]}% of failing mail'])
        if tags['pct'].isdigit() and int(tags['pct']) < 100:
            _note(notes, 'info', f'The policy applies to only {tags["pct"]}% of failing mail.')
    for key, label in (('adkim', 'DKIM'), ('aspf', 'SPF')):
        if key in tags:
            strict = tags[key].lower() == 's'
            out['details'].append([f'{key}={tags[key]}', f'{label} domain must match '
                                   + ('exactly' if strict else 'the main domain (subdomains count)')])
    if 'rua' in tags:
        out['details'].append(['rua=' + tags['rua'], 'Daily summary reports go here'])
    else:
        _note(notes, 'warning', 'No rua= address, so nobody receives the reports.',
              'Add rua=mailto:an-address-you-read. The reports show who is sending mail as your domain.')
    if 'ruf' in tags:
        out['details'].append(['ruf=' + tags['ruf'], 'Per-message failure reports go here (few providers send them)'])

    if effective == 'none':
        _note(notes, 'warning', 'The policy is "none": forged mail using this domain is still delivered.',
              'That is the right place to start. Once the reports show your real mail passing, '
              'move to p=quarantine and later p=reject.')
        return _summarise(out, '')
    return _summarise(out, f'DMARC is on, with policy "{effective}".')


# ---------------------------------------------------------------- DKIM

def _key_bits(p_value):
    try:
        der = base64.b64decode(re.sub(r'\s+', '', p_value) + '==')
    except Exception:
        return None
    n = len(der)
    if n >= 540:
        return 4096
    if n >= 390:
        return 3072
    if n >= 290:
        return 2048
    if n >= 160:
        return 1024
    return 512 if n >= 90 else None


def _dkim_one(domain, selector):
    res = _resolver()
    res.lifetime = 3
    values, status = _txt(res, f'{selector}._domainkey.{domain}')
    return selector, values, status


def dkim_check(domain, selector=None, res=None):
    out = _result('dkim', domain)
    notes = out['notes']
    selector = (selector or '').strip().lower().rstrip('.')
    if selector.endswith('._domainkey'):
        selector = selector[:-len('._domainkey')]
    if selector and not SELECTOR_RE.fullmatch(selector):
        out['summary'] = {'level': 'error', 'text': 'That selector does not look right. It is a short name such as "google" or "selector1".'}
        return out

    selectors = [selector] if selector else COMMON_SELECTORS
    with ThreadPoolExecutor(max_workers=10) as pool:
        answers = list(pool.map(lambda s: _dkim_one(domain, s), selectors))
    found = [(s, v) for s, v, st in answers if v]
    if selector and answers[0][2] == 'error':
        return _lookup_failed(out)

    if not found:
        if selector:
            _note(notes, 'error', f'No record at {selector}._domainkey.{domain}.',
                  'Check the selector spelling, and that the record was added as a TXT (or CNAME) on exactly that name.')
            return _summarise(out, '', 'No DKIM key found for that selector.')
        _note(notes, 'info', 'DNS cannot list DKIM selectors, so we tried the names the common mail services use and found none.',
              'To find yours, open an email sent from the domain, view its original source, and look for '
              '"s=" in the DKIM-Signature header. Enter that value as the selector.')
        out['summary'] = {'level': 'warning', 'text': 'No DKIM key found under the common selector names.'}
        return out

    if not selector and len(found) > 6 and len({v[0] for _, v in found}) == 1:
        # A wildcard TXT record answers for every selector name
        found = [('*', found[0][1])]
        _note(notes, 'info', 'This domain answers the same way for every selector name (a wildcard record).')

    for sel, values in found:
        value = values[0].strip()
        out['records'].append({'label': f'{sel}._domainkey', 'value': value if len(value) < 140 else value[:120] + '…'})
        if len(values) > 1:
            _note(notes, 'error', f'{sel}: {len(values)} TXT records on the same name.',
                  'Verifiers cannot tell which is the key. Keep one.')
        if '"' in value:
            _note(notes, 'error', f'{sel}: the value contains quote characters as part of the text.',
                  'The key was pasted with its quotes into a provider that adds quotes itself. '
                  'Delete the record and paste the value again without any quote marks.')
        tags = {}
        for part in value.replace('"', '').split(';'):
            if '=' in part:
                k, v = part.split('=', 1)
                tags[k.strip().lower()] = v.strip()
        if 'p' not in tags:
            out['details'].append([sel, 'Not a DKIM key'])
            _note(notes, 'error', f'{sel}: the record has no p= part, so it is not a usable DKIM key.')
            continue
        if not tags['p']:
            out['details'].append([sel, 'Revoked key (empty p=)'])
            _note(notes, 'warning', f'{sel}: the key is revoked. Mail signed with this selector fails DKIM.')
            continue
        ktype = tags.get('k', 'rsa').lower()
        if ktype == 'ed25519':
            out['details'].append([sel, 'Ed25519 key'])
            continue
        bits = _key_bits(tags['p'])
        if bits is None:
            out['details'].append([sel, 'RSA key that could not be read'])
            _note(notes, 'error', f'{sel}: the key is damaged or cut short.',
                  'Copy the whole value again from your mail service. Long keys are often cut at 255 characters.')
        else:
            out['details'].append([sel, f'RSA key, about {bits} bits'])
            if bits < 1024:
                _note(notes, 'error', f'{sel}: a {bits}-bit key is too short. Gmail and others ignore it.',
                      'Generate a new 2048-bit key at your mail service.')
            elif bits == 1024:
                _note(notes, 'warning', f'{sel}: 1024-bit key. It still works, but 2048 bits is the current standard.')
        if 't' in tags and 'y' in tags['t'].lower():
            _note(notes, 'warning', f'{sel}: the record is flagged as "testing" (t=y), so receivers may ignore failures.')

    if not selector:
        _note(notes, 'info', 'Only common selector names were tried. If your mail service uses another, enter it to check that one.')
    count = len(found)
    return _summarise(out, f'Found {count} DKIM key{"s" if count != 1 else ""}: ' + ', '.join(s for s, _ in found) + '.')


# ---------------------------------------------------------------- entry point

TOOLS = {'mx': mx_lookup, 'spf': spf_check, 'dmarc': dmarc_check, 'dkim': dkim_check}


def run(tool, raw_domain, selector=None):
    domain = clean_domain(raw_domain)
    if not domain or len(domain) > 253 or not DOMAIN_RE.fullmatch(domain):
        return {'error': 'That does not look like a domain. Enter something like example.com.'}
    if tool == 'all':
        res = _resolver()
        return {'tool': 'all', 'domain': domain, 'results': [
            mx_lookup(domain, res), spf_check(domain, res),
            dkim_check(domain, selector), dmarc_check(domain, res)]}
    if tool not in TOOLS:
        return {'error': 'Unknown tool.'}
    if tool == 'dkim':
        return dkim_check(domain, selector)
    return TOOLS[tool](domain)


if __name__ == '__main__':
    import json
    import sys
    print(json.dumps(run(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None), indent=1))
