#!/usr/bin/env python3
"""
From-header alignment for forwarded mail (DMARC).

A forwarded message leaves from catchall.mx's IP, so SPF can never align with
the original From: domain. Alignment then depends on the original sender's
DKIM signature. This module decides, per message:

  * original DKIM verifies and matches the From: domain -> forward untouched
  * rspamd flagged it as spam, or it fails the sender's own DMARC policy
    -> forward untouched (catchall.mx must not vouch for it)
  * otherwise -> rewrite From: to forwarded@catchall.mx (real sender kept in
    Reply-To and the display name) and DKIM-sign as catchall.mx

Kill switch:  redis-cli set config:from_rewrite off
"""
import re
import logging
import email.utils
from email.header import decode_header, make_header

import dkim
import redis

FWD_ADDR = 'forwarded@catchall.mx'
SIGN_DOMAIN = b'catchall.mx'
SIGN_SELECTOR = b'rs1'
# One copy of the signing key per account that forwards mail (Postfix pipe
# runs as nobody, the web API as www-data, cron as root).
KEY_PATHS = [
    '/etc/catchall/dkim/rs1.nobody.key',
    '/etc/catchall/dkim/rs1.www-data.key',
    '/var/lib/rspamd/dkim/catchall.mx.rs1.key',
]
SIGN_HEADERS = [
    b'from', b'reply-to', b'to', b'cc', b'subject', b'date', b'message-id',
    b'mime-version', b'content-type', b'x-original-from',
]
# rspamd symbols meaning "failed the sender's published DMARC policy"
DMARC_FAIL_SYMBOLS = (b'DMARC_POLICY_REJECT', b'DMARC_POLICY_QUARANTINE')

log = logging.getLogger(__name__)


def to_bytes(content):
    if isinstance(content, bytes):
        return content
    return content.encode('utf-8', 'surrogateescape')


def _split(raw):
    """Return (list of raw header fields, body). Each field keeps its folding."""
    m = re.search(rb'\r\n\r\n', raw)
    if m:
        head, body = raw[:m.start()], raw[m.end():]
    else:
        head, body = raw.rstrip(b'\r\n'), b''
    fields = []
    for line in head.split(b'\r\n'):
        if line[:1] in (b' ', b'\t') and fields:
            fields[-1] += b'\r\n' + line
        else:
            fields.append(line)
    return fields, body


def _name(field):
    return field.split(b':', 1)[0].strip().lower()


def _value(field):
    """Unfolded header value as text."""
    v = field.split(b':', 1)[1] if b':' in field else b''
    v = re.sub(rb'\r\n([ \t])', rb'\1', v).strip()
    return v.decode('utf-8', 'replace')


def _first(fields, name):
    for f in fields:
        if _name(f) == name:
            return f
    return None


def _related(a, b):
    """Relaxed alignment: same domain or one is a subdomain of the other."""
    a, b = a.lower().rstrip('.'), b.lower().rstrip('.')
    return bool(a and b) and (a == b or a.endswith('.' + b) or b.endswith('.' + a))


def _dkim_aligned(raw, fields, from_domain):
    """True if any DKIM signature verifies and its d= matches the From domain."""
    count = sum(1 for f in fields if _name(f) == b'dkim-signature')
    for idx in range(count):
        try:
            d = dkim.DKIM(raw, logger=None)
            if d.verify(idx=idx) and _related(d.domain.decode('ascii', 'replace'), from_domain):
                return True
        except Exception:
            continue
    return False


def _load_key():
    for path in KEY_PATHS:
        try:
            with open(path, 'rb') as f:
                return f.read()
        except OSError:
            continue
    return None


def _enabled():
    try:
        r = redis.Redis(host='localhost', port=6379, decode_responses=True,
                        socket_timeout=2)
        return (r.get('config:from_rewrite') or 'on').lower() != 'off'
    except Exception:
        return True


def _display(name, addr):
    """Display name for the rewritten From, e.g. 'Jane Doe - jane at bank.com via CatchAll'."""
    shown = addr.replace('@', ' at ')
    label = f"{name} - {shown}" if name and name.lower() != addr.lower() else shown
    label = re.sub(r'[\r\n\t"<>\\]', ' ', label)
    label = re.sub(r'\s+', ' ', label).strip()[:110]
    return f"{label} via CatchAll"


def prepare_for_forward(content, domain=''):
    """
    Return the message as bytes (CRLF line endings), with From: rewritten and
    a catchall.mx DKIM signature added when the original would fail DMARC
    alignment. Never raises: on any problem the original message is returned.
    """
    raw = re.sub(rb'\r?\n', b'\r\n', to_bytes(content))
    try:
        if not _enabled():
            return raw

        fields, body = _split(raw)
        from_field = _first(fields, b'from')
        orig_from = _value(from_field) if from_field else ''
        try:
            decoded = str(make_header(decode_header(orig_from)))
        except Exception:
            decoded = orig_from
        name, addr = email.utils.parseaddr(decoded)
        from_domain = addr.rsplit('@', 1)[1] if '@' in addr else ''

        if from_domain and _dkim_aligned(raw, fields, from_domain):
            log.info(f"From alignment [{domain}]: original DKIM aligned with {from_domain}, untouched")
            return raw

        spam_status = _first(fields, b'x-spam-status')
        if spam_status and _value(spam_status).lower().startswith('yes'):
            log.info(f"From alignment [{domain}]: flagged as spam by rspamd, untouched")
            return raw

        spamd_result = _first(fields, b'x-spamd-result')
        if spamd_result and any(s in spamd_result for s in DMARC_FAIL_SYMBOLS):
            log.info(f"From alignment [{domain}]: fails DMARC policy of {from_domain}, untouched")
            return raw

        key = _load_key()
        if not key:
            log.error(f"From alignment [{domain}]: signing key not readable, untouched")
            return raw

        new_from = email.utils.formataddr((_display(name, addr or 'unknown sender'), FWD_ADDR))
        has_reply_to = _first(fields, b'reply-to') is not None
        clean_orig = re.sub(r'[\r\n]+', ' ', orig_from).strip()

        out, placed = [], False
        for f in fields:
            n = _name(f)
            if n in (b'arc-seal', b'arc-message-signature', b'arc-authentication-results'):
                continue  # the seal covered the old From and would now fail
            if n == b'from':
                if not placed:
                    out.append(b'From: ' + new_from.encode('ascii', 'replace'))
                    placed = True
                continue
            out.append(f)
        if not placed:
            out.append(b'From: ' + new_from.encode('ascii', 'replace'))
        if clean_orig:
            safe = clean_orig.encode('utf-8', 'replace')
            if not has_reply_to and addr:
                out.append(b'Reply-To: ' + safe)
            out.append(b'X-Original-From: ' + safe)

        rewritten = b'\r\n'.join(out) + b'\r\n\r\n' + body
        signature = dkim.sign(
            message=rewritten,
            selector=SIGN_SELECTOR,
            domain=SIGN_DOMAIN,
            privkey=key,
            include_headers=SIGN_HEADERS,
        )
        log.info(f"From alignment [{domain}]: rewrote From ({addr or 'none'}) and signed as catchall.mx")
        return signature + rewritten

    except Exception as e:
        log.error(f"From alignment [{domain}]: error {e!r}, forwarding untouched")
        return raw
