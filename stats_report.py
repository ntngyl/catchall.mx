#!/usr/bin/env python3
"""Build the private service statistics page (/stats/) for catchall.mx.

Reads counters from Redis, the forwarder log, the Postfix log and rspamd, and
writes a plain HTML page. Daily totals (overall and per domain) are kept as
numbers only in /var/lib/catchall-stats/ so the history outlives the 7-day mail
logs; no email addresses or message content are stored there.
"""
import glob, gzip, json, os, re, subprocess, sys, time
from datetime import datetime, timezone, timedelta
from html import escape

import redis

STATE = '/var/lib/catchall-stats/daily.json'
DOMAIN_STATE = '/var/lib/catchall-stats/domains.json'
OUT = sys.argv[1] if len(sys.argv) > 1 else '/var/www/stats/index.html'
MONTHS = {m: i + 1 for i, m in enumerate('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split())}

FORWARDER = [  # (counter, text found in the forwarder log line)
    ('received', 'Processing email for'),
    ('forwarded', 'Successfully forwarded to'),
    ('forwarded', 'Successfully forwarded queued email to'),
    ('spam', 'SPAM/PHISHING detected'),
    ('held', 'not verified - queueing'),
    ('held', 'not confirmed yet - queueing'),
    ('refused', 'all MX servers failed'),
    ('no_address', 'No forward address found'),
    ('rule_blocked', 'rules (blocked)'),
    ('rewritten', 'rewrote From'),
    ('untouched', 'untouched'),
]
MAIL = [
    ('pregreet', 'PREGREET'),
    ('blocklisted', 'DNSBL rank'),
]
COLS = ['received', 'forwarded', 'spam', 'held', 'refused', 'connections', 'door']


def lines(pattern):
    for path in sorted(glob.glob(pattern)):
        opener = gzip.open if path.endswith('.gz') else open
        try:
            with opener(path, 'rt', errors='replace') as f:
                yield from f
        except OSError:
            continue


def mail_day(line, year):
    if line[:4].isdigit():
        return line[:10]
    m = MONTHS.get(line[:3])
    try:
        return f'{year}-{m:02d}-{int(line[4:6]):02d}' if m else None
    except ValueError:
        return None


def collect():
    days = {}
    def bump(day, key):
        days.setdefault(day, {})[key] = days.get(day, {}).get(key, 0) + 1
    domains, per_domain, current = {}, {}, None
    for ln in lines('/var/log/catchall/forwarder.log*'):
        day = ln[:10]
        if not re.fullmatch(r'\d{4}-\d\d-\d\d', day):
            continue
        if 'Processing email for' in ln:
            m = re.search(r'\(domain: ([^)]+)\)|Processing email for (\S+)$', ln.strip())
            current = (m.group(1) or m.group(2)).split('@')[-1].lower().rstrip('.') if m else None
            if current:
                domains.setdefault(day, set()).add(current)
        for key, text in FORWARDER:
            if text in ln:
                bump(day, key)
                if current:
                    d = per_domain.setdefault(current, {}).setdefault(day, {})
                    d[key] = d.get(key, 0) + 1
    year = datetime.now(timezone.utc).year
    for ln in lines('/var/log/mail.log*'):
        day = mail_day(ln, year)
        if not day:
            continue
        for key, text in MAIL:
            if text in ln:
                bump(day, key)
        if 'postfix/postscreen' in ln and ': CONNECT from ' in ln:
            bump(day, 'connections')
        if 'NOQUEUE: reject' in ln:
            bump(day, 'deferred' if ' 450 ' in ln else 'rejected')
    for day, names in domains.items():
        days[day]['domains'] = len(names)
    return days, per_domain


def merged(fresh, snapshot):
    try:
        with open(STATE) as f:
            state = json.load(f)
    except (OSError, ValueError):
        state = {}
    for day, counts in fresh.items():
        old = state.setdefault(day, {})
        for k, v in counts.items():
            old[k] = max(v, old.get(k, 0))      # logs only ever grow within a day
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    state.setdefault(today, {}).update({'active': snapshot['active'], 'dkim': snapshot['dkim']})
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    with open(STATE + '.tmp', 'w') as f:
        json.dump(state, f, sort_keys=True)
    os.replace(STATE + '.tmp', STATE)
    return state


def merged_domains(fresh):
    try:
        with open(DOMAIN_STATE) as f:
            state = json.load(f)
    except (OSError, ValueError):
        state = {}
    for domain, days in fresh.items():
        for day, counts in days.items():
            old = state.setdefault(domain, {}).setdefault(day, {})
            for k, v in counts.items():
                old[k] = max(v, old.get(k, 0))
    fd = os.open(DOMAIN_STATE + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(state, f, sort_keys=True)
    os.replace(DOMAIN_STATE + '.tmp', DOMAIN_STATE)
    return state


def domain_status():
    """Current state of every domain known to the service, from Redis."""
    r = redis.Redis(decode_responses=True)
    def names(prefix):
        return {k.split(':', 1)[1].lower() for k in r.scan_iter(prefix + ':*', count=500)}
    active = {}
    for k in r.scan_iter('active:*', count=500):
        try:
            active[k.split(':', 1)[1].lower()] = int(r.get(k) or 0)
        except ValueError:
            active[k.split(':', 1)[1].lower()] = 0
    blocked = {d.lower() for d in r.smembers('abuse:domains')} if r.type('abuse:domains') == 'set' else set()
    return {'active': active, 'dkim': names('dkim'), 'consent': names('consent'),
            'pending': names('verify'), 'blocked': blocked}


def domain_rows(dstate, status, week):
    known = set(dstate) | set(status['active']) | status['pending'] | status['dkim']
    out = []
    for dom in known:
        days = dstate.get(dom, {})
        def tot(key, since=None):
            return sum(c.get(key, 0) for d, c in days.items() if not since or d >= since)
        if dom in status['blocked']:
            state, order = 'Blocked', 4
        elif dom in status['active'] and time.time() - status['active'][dom] <= 30 * 86400:
            state, order = 'Active', 0
        elif dom in status['active']:
            state, order = 'Dormant', 1
        elif dom in status['pending']:
            state, order = 'Waiting', 2
        else:
            state, order = 'Unconfirmed', 3
        since = status['active'].get(dom)
        mail_days = [d for d, c in days.items() if c.get('received')]
        if order == 3 and (dom == 'catchall.mx' or dom.endswith('.invalid')
                           or tot('no_address') >= tot('received')):
            continue
        out.append({
            'domain': dom, 'state': state, 'order': order,
            'since': datetime.fromtimestamp(since, timezone.utc).strftime('%-d %b %Y') if since else '',
            'dkim': dom in status['dkim'], 'consent': dom in status['consent'],
            'r7': tot('received', week), 'f7': tot('forwarded', week),
            'r': tot('received'), 'f': tot('forwarded'), 'spam': tot('spam'),
            'held': tot('held'), 'refused': tot('refused'),
            'last': datetime.strptime(max(mail_days), '%Y-%m-%d').strftime('%-d %b') if mail_days else '',
        })
    out.sort(key=lambda x: (x['order'], -x['r7'], -x['r'], -(status['active'].get(x['domain']) or 0), x['domain']))
    return out


def count_keys(r, pattern):
    return sum(1 for _ in r.scan_iter(pattern, count=500))


def files_in(path):
    return sum(len(f) for _, _, f in os.walk(path))


def rspamd():
    out = {}
    try:
        text = subprocess.run(['rspamc', 'stat'], capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return out
    for key, pat in (('scanned', r'Messages scanned: (\d+)'), ('spam', r'treated as spam: (\d+)'),
                     ('learned_ham', r'BAYES_HAM.*?learned: (\d+)'), ('learned_spam', r'BAYES_SPAM.*?learned: (\d+)')):
        m = re.search(pat, text)
        if m:
            out[key] = int(m.group(1))
    return out


def snapshot():
    r = redis.Redis(decode_responses=True)
    try:
        q = subprocess.run(['postqueue', '-j'], capture_output=True, text=True, timeout=20).stdout
        postfix_queue = len([l for l in q.splitlines() if l.strip()])
    except Exception:
        postfix_queue = 0
    blocked = {d.lower() for d in r.smembers('abuse:domains')} if r.type('abuse:domains') == 'set' else set()
    confirmed, recent = set(), set()
    for k in r.scan_iter('active:*', count=500):
        name = k.split(':', 1)[1].lower()
        confirmed.add(name)
        try:
            if time.time() - int(r.get(k) or 0) <= 30 * 86400:
                recent.add(name)
        except ValueError:
            pass
    return {
        'active': len(recent - blocked), 'dormant': len(confirmed - recent - blocked),
        'active_blocked': len(confirmed & blocked),
        'dkim': count_keys(r, 'dkim:*'),
        'consent': count_keys(r, 'consent:*'), 'pending': count_keys(r, 'verify:*'),
        'blocked_domains': r.scard('abuse:domains') if r.type('abuse:domains') == 'set' else 0,
        'waiting': files_in('/var/spool/catchall/queue'),
        'quarantine': files_in('/var/spool/catchall/quarantine'),
        'postfix_queue': postfix_queue,
    }


def n(v):
    return f'{v:,}'


def render(state, snap, spam, dstate, status):
    now = datetime.now(timezone.utc)
    today = now.strftime('%Y-%m-%d')
    def total(keys, since=None):
        return sum(c.get(k, 0) for d, c in state.items() if not since or d >= since for k in keys)
    week = (now - timedelta(days=6)).strftime('%Y-%m-%d')
    door = ['pregreet', 'blocklisted', 'rejected']
    t = state.get(today, {})

    def tile(label, value, note=''):
        return (f'<div class="tile"><span class="k">{escape(label)}</span><b>{value}</b>'
                f'<span class="n">{escape(note)}</span></div>')

    tiles_domains = ''.join([
        tile('Active domains', n(snap['active']), 'confirmed, with mail forwarded or confirmed in the last 30 days'),
        tile('Dormant domains', n(snap['dormant']), 'confirmed earlier, quiet for 30+ days'),
        tile('With DKIM signing', n(snap['dkim'])),
        tile('Waiting for confirmation', n(snap['pending']), 'link sent, not yet clicked'),
        tile('Blocked for abuse', n(snap['blocked_domains']), f"domains; {n(snap['active_blocked'])} of them had been confirmed"),
    ])
    recv7, fwd7 = total(['received'], week), total(['forwarded'], week)
    tiles_mail = ''.join([
        tile('Received today', n(t.get('received', 0)), f"{n(t.get('forwarded', 0))} forwarded"),
        tile('Received, last 7 days', n(recv7), f'{n(fwd7)} forwarded'),
        tile('Forwarded, all recorded days', n(total(['forwarded'])), f"of {n(total(['received']))} received"),
        tile('Held for confirmation now', n(snap['waiting']), 'messages on disk'),
        tile('In the delivery queue now', n(snap['postfix_queue']), 'messages being retried'),
    ])
    tiles_spam = ''.join([
        tile('Turned away at the door, 7 days', n(total(door, week)),
             f"of {n(total(['connections'], week))} connections"),
        tile('Discarded as spam, 7 days', n(total(['spam'], week)), 'by the keyword filter'),
        tile('Refused by the destination, 7 days', n(total(['refused'], week)), 'Gmail and others said no'),
        tile('Scored by the learning filter', n(spam.get('scanned', 0)),
             f"{n(spam.get('spam', 0))} flagged as spam (not acted on)"),
        tile('Learned so far', f"{n(spam.get('learned_ham', 0))} / {n(spam.get('learned_spam', 0))}",
             'legitimate / spam; needs 200 of each'),
    ])

    rows = ''
    for day in sorted(state, reverse=True)[:60]:
        c = state[day]
        d = sum(c.get(k, 0) for k in door)
        label = datetime.strptime(day, '%Y-%m-%d').strftime('%a %-d %b')
        cells = [c.get('received', 0), c.get('forwarded', 0), c.get('spam', 0), c.get('held', 0),
                 c.get('refused', 0), c.get('domains', 0)]
        seen_door = 'connections' in c
        rows += (f'<tr><th scope="row">{label}{" (so far)" if day == today else ""}</th>'
                 + ''.join(f'<td>{n(v) if v else "<i>0</i>"}</td>' for v in cells)
                 + (f'<td>{n(c["connections"])}</td><td>{n(d)}</td>' if seen_door else '<td><i>–</i></td><td><i>–</i></td>')
                 + f'<td>{n(c["active"]) if c.get("active") else "<i>–</i>"}</td></tr>')

    def num(v):
        return n(v) if v else '<i>0</i>'
    tone = {'Active': 'good', 'Blocked': 'bad'}  # other states stay neutral
    drows, listed = '', domain_rows(dstate, status, week)
    for x in listed:
        drows += (f'<tr><th scope="row">{escape(x["domain"])}</th>'
                  f'<td class="l"><span class="st {tone.get(x["state"], "")}">{x["state"]}</span></td>'
                  f'<td class="l">{x["since"] or "<i>–</i>"}</td>'
                  f'<td class="l">{"Yes" if x["dkim"] else "<i>–</i>"}</td>'
                  f'<td class="l">{"Yes" if x["consent"] else "<i>–</i>"}</td>'
                  + (f'<td>{n(x["r7"])} / {n(x["f7"])}</td>' if x['r7'] else '<td><i>0</i></td>')
                  + (f'<td>{n(x["r"])} / {n(x["f"])}</td>' if x['r'] else '<td><i>0</i></td>')
                  + ''.join(f'<td>{num(x[k])}</td>' for k in ('spam', 'held', 'refused'))
                  + f'<td>{x["last"] or "<i>–</i>"}</td></tr>')
    quiet_blocked = len(status['blocked'] - {x['domain'] for x in listed})
    counts = {}
    for x in listed:
        counts[x['state']] = counts.get(x['state'], 0) + 1
    dsummary = ', '.join(f'{v} {k.lower()}' for k, v in sorted(counts.items(), key=lambda kv: -kv[1]))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex">
    <meta http-equiv="refresh" content="600">
    <title>Service stats - CatchAll.mx</title>
    <link rel="stylesheet" href="/site.css?v=5">
    <style>
        main {{ padding: 44px 0 80px; }}
        h1 {{ font-size: 34px; letter-spacing: -.035em; line-height: 1.1; }}
        .when {{ color: var(--soft); margin: 8px 0 0; font-size: 15px; }}
        h2 {{ font-size: 15px; font-weight: 650; margin: 44px 0 14px; }}
        .tiles {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }}
        @media (max-width: 900px) {{ .tiles {{ grid-template-columns: repeat(2, 1fr); }} }}
        .tile {{ border: 1px solid var(--line); border-radius: 12px; padding: 16px 16px 14px; display: flex; flex-direction: column; gap: 4px; }}
        .tile .k {{ font-size: 13.5px; color: var(--soft); line-height: 1.35; min-height: 2.7em; }}
        .tile b {{ font-size: 30px; letter-spacing: -.03em; line-height: 1.1; font-variant-numeric: tabular-nums; }}
        .tile .n {{ font-size: 13px; color: var(--faint); line-height: 1.4; }}
        .scroll {{ overflow-x: auto; border: 1px solid var(--line); border-radius: 12px; }}
        table {{ margin: 0; font-size: 14.5px; min-width: 720px; }}
        th, td {{ padding: 9px 12px; text-align: right; border-bottom: 1px solid var(--line); white-space: nowrap; font-variant-numeric: tabular-nums; }}
        thead th {{ font-weight: 600; font-size: 13px; color: var(--soft); background: var(--wash); white-space: normal; vertical-align: bottom; }}
        th[scope=row], thead th:first-child {{ text-align: left; font-weight: 500; }}
        tbody tr:last-child th, tbody tr:last-child td {{ border-bottom: 0; }}
        td i {{ font-style: normal; color: var(--faint); }}
        td.l, thead th.l {{ text-align: left; }}
        .domains {{ min-width: 900px; }} .domains th, .domains td {{ padding: 8px 9px; }}
        .domains th[scope=row] {{ font-family: var(--mono); font-size: 13.5px; max-width: 230px; overflow: hidden; text-overflow: ellipsis; }}
        .st {{ color: var(--soft); }} .st.good {{ color: var(--good); }} .st.bad {{ color: var(--bad); }}
        h2 small {{ font-weight: 400; color: var(--soft); margin-left: 8px; }}
        .top nav {{ display: flex; align-items: center; gap: 20px; font-size: 15px; }}
        .top nav a {{ text-decoration: none; color: var(--soft); }} .top nav a:hover, .top nav a.on {{ color: var(--ink); }}
        .top form {{ display: inline; }}
        .top button {{ font: inherit; color: var(--soft); background: none; border: 0; cursor: pointer; padding: 0; }}
        .top button:hover {{ color: var(--ink); }}
        .top nav a {{ display: inline !important; }}
        @media (max-width: 560px) {{ .top nav {{ gap: 13px; font-size: 14px; }} .logo {{ font-size: 0; gap: 0; }} h1 {{ font-size: 28px; }} }}
        .foot {{ color: var(--soft); font-size: 14px; margin-top: 18px; max-width: 760px; }}
    </style>
</head>
<body>
    <header class="top"><div class="wrap">
        <a class="logo" href="/"><i></i>catchall.mx</a>
        <nav>
            <a class="on" href="/stats/">Service</a>
            <a href="/stats/visitors.html">Visitors</a>
            <a href="/stats/bots.html">Crawlers</a>
            <form method="post" action="/stats/logout"><button type="submit">Sign out</button></form>
        </nav>
    </div></header>
    <main><div class="wrap">
        <h1>Service stats</h1>
        <p class="when">Updated {now.strftime('%-d %b %Y, %H:%M')} UTC. Rebuilt every 10 minutes.</p>

        <h2>Domains</h2>
        <div class="tiles">{tiles_domains}</div>

        <h2>Mail</h2>
        <div class="tiles">{tiles_mail}</div>

        <h2>Spam and refusals</h2>
        <div class="tiles">{tiles_spam}</div>

        <h2>Day by day</h2>
        <div class="scroll"><table>
            <thead><tr><th>Day (UTC)</th><th>Received</th><th>Forwarded</th><th>Spam discarded</th>
            <th>Held</th><th>Refused</th><th>Domains with mail</th>
            <th>Connections</th><th>Turned away</th><th>Active domains</th></tr></thead>
            <tbody>{rows}</tbody>
        </table></div>
        <h2>Domain list <small>{len(listed)} listed: {dsummary}</small></h2>
        <div class="scroll"><table class="domains">
            <thead><tr><th>Domain</th><th class="l">Status</th><th class="l">Last active</th><th class="l">DKIM</th>
            <th class="l">Consent</th><th>7 days in / out</th><th>All in / out</th><th>Spam</th><th>Held</th><th>Refused</th><th>Last mail</th></tr></thead>
            <tbody>{drows}</tbody>
        </table></div>
        <p class="foot">Every domain that is active, waiting for confirmation, has a DKIM key, or has received
        mail since 18 November. In / out is messages received and forwarded. Last active is the last time
        mail was forwarded or the destination was confirmed. Dormant domains are asked to confirm again when their
        next message arrives. Waiting means a confirmation link was sent and not yet clicked. Unconfirmed means the domain pointed here and mail arrived, but nobody confirmed the destination.
        {quiet_blocked} more blocked domains have no mail on record and are not listed. Consent shows domains
        confirmed under the per-destination consent system; older active domains were confirmed before it existed.</p>

        <p class="foot">Held means waiting for the owner to confirm; Refused means the destination mailbox provider said no. Received counts messages that passed the door checks and reached the forwarder.
        Turned away at the door counts senders stopped before sending anything: on a blocklist, talking
        out of turn, or addressed to a domain we do not serve. Door figures start on 24 November, when
        the service moved to this server. Only daily totals are kept, overall and per domain; no email addresses or message content.</p>
    </div></main>
</body>
</html>
"""


if __name__ == '__main__':
    snap = snapshot()
    days, per_domain = collect()
    state = merged(days, snap)
    html = render(state, snap, rspamd(), merged_domains(per_domain), domain_status())
    with open(OUT + '.tmp', 'w') as f:
        f.write(html)
    os.replace(OUT + '.tmp', OUT)
