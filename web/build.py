#!/usr/bin/env python3
"""
Builds the static guide and tool pages of catchall.mx.

    python3 web/build.py          (writes into web/guides, web/tools, sitemap.xml, robots.txt)

The homepage (index.html) and the record builder (setup/index.html) are written
by hand and are not touched. Provider details here must stay in step with the
PROVIDERS table in setup/index.html; both were checked against the providers'
own help pages in November 2026.
"""
import html
import os
from datetime import date

ROOT = os.path.dirname(os.path.abspath(__file__))
SITE = 'https://catchall.mx'
MX_HOST = 'mail.catchall.mx'
CSS_VERSION = "2"
esc = html.escape

FAVICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' "
           "rx='7' fill='%230a0a0a'/%3E%3Cpath d='M8 12l8 6 8-6' fill='none' stroke='%23ffffff' stroke-width='2.4' "
           "stroke-linecap='round' stroke-linejoin='round'/%3E%3Crect x='8' y='10' width='16' height='12' rx='2' fill='none' "
           "stroke='%23ffffff' stroke-width='2.4'/%3E%3C/svg%3E")

written = []


def page(path, title, description, body, here=''):
    """Write one page. path is like 'tools/mx-lookup' (no slashes at the ends)."""
    url = f'{SITE}/{path}/'
    nav = ''.join(f'<a href="{h}"{" class=here" if key == here else ""}>{label}</a>'
                  for key, h, label in (('home', '/#setup', 'How it works'), ('guides', '/guides/', 'Setup guides'),
                                        ('tools', '/tools/', 'DNS tools')))
    doc = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{esc(title)}</title>
    <meta name="description" content="{esc(description)}">
    <meta name="robots" content="index, follow">
    <link rel="canonical" href="{url}">
    <meta property="og:type" content="article">
    <meta property="og:url" content="{url}">
    <meta property="og:title" content="{esc(title)}">
    <meta property="og:description" content="{esc(description)}">
    <meta property="og:image" content="{SITE}/og-image.png">
    <meta property="og:site_name" content="CatchAll.mx">
    <meta name="twitter:card" content="summary_large_image">
    <link rel="icon" type="image/svg+xml" href="{FAVICON}">
    <link rel="stylesheet" href="/site.css?v={CSS_VERSION}">
</head>
<body>
    <header class="top">
        <div class="wrap">
            <a class="logo" href="/"><i></i>catchall.mx</a>
            <nav>{nav}<a class="cta" href="/setup/">Record builder</a></nav>
        </div>
    </header>
    <main>
{body}
    </main>
    <footer>
        <div class="wrap">
            <span>catchall.mx is a small, free email forwarder.</span>
            <nav>
                <a href="/guides/">Setup guides</a>
                <a href="/tools/">DNS tools</a>
                <a href="/setup/">Record builder</a>
                <a href="/report">Report abuse</a>
                <a href="https://github.com/ntngyl/catchall.mx" target="_blank" rel="noopener">Source</a>
            </nav>
        </div>
    </footer>
    <script src="/tools.js?v={CSS_VERSION}" defer></script>
</body>
</html>
'''
    target = os.path.join(ROOT, path)
    os.makedirs(target, exist_ok=True)
    with open(os.path.join(target, 'index.html'), 'w') as f:
        f.write(doc)
    written.append(path)


def head(crumbs, h1, lede, extra=''):
    trail = ' / '.join(f'<a href="{h}">{esc(t)}</a>' for t, h in crumbs)
    return f'''        <section class="head"><div class="wrap">
            <p class="crumbs">{trail}</p>
            <h1>{h1}</h1>
            <p class="lede">{lede}</p>
{extra}
        </div></section>'''


def sec(title, body, small=''):
    sm = f'<small>{small}</small>' if small else ''
    return f'''        <section class="sec"><div class="wrap">
            <h2>{title}{sm}</h2>
            <div class="body">
{body}
            </div>
        </div></section>'''


def links(items):
    return '<ul class="links">' + ''.join(
        f'<li><a href="{h}"><b>{esc(t)}</b><span>{esc(d)}</span><i>→</i></a></li>' for t, d, h in items) + '</ul>'


# ------------------------------------------------------------------ DNS tools

def tool_box(tool, button, selector=False):
    sel = ('<input type="text" id="selector" class="narrow" placeholder="selector (optional)" '
           'autocomplete="off" autocapitalize="none" spellcheck="false" aria-label="DKIM selector">') if selector else ''
    return f'''            <div class="check" data-tool="{tool}" style="margin-top:30px">
                <label for="domain">Domain to look up</label>
                <div class="input-group">
                    <input type="text" id="domain" placeholder="example.com" autocomplete="off" autocapitalize="none" spellcheck="false">
                    {sel}<button class="btn">{button}</button>
                </div>
                <div id="out" aria-live="polite"></div>
                <p class="foot">Reads public DNS only. Lookups are not saved, and there is nothing to sign up for.</p>
            </div>'''


TOOLS = [
    ('Email DNS check', 'MX, SPF, DKIM and DMARC for a domain in one go.', '/tools/'),
    ('MX lookup', 'Which servers receive mail for a domain, and whether they resolve.', '/tools/mx-lookup/'),
    ('SPF checker', 'Reads the SPF record term by term and counts its DNS lookups.', '/tools/spf-checker/'),
    ('DKIM checker', 'Finds a domain\'s DKIM keys and checks they are usable.', '/tools/dkim-checker/'),
    ('DMARC checker', 'Shows the DMARC policy and what it does to forged mail.', '/tools/dmarc-checker/'),
]


def other_tools(current):
    return sec('More tools', links([t for t in TOOLS if t[2] != current]
                                   + [('Free email forwarding', 'Every address at your domain, delivered to the inbox you already use.', '/')]))


def build_tools():
    crumb = [('catchall.mx', '/'), ('DNS tools', '/tools/')]

    # ---- all-in-one
    body = head(crumb[:1], 'Check a domain\'s email DNS',
                'One lookup for the four things that decide whether a domain\'s email works and is trusted: '
                'MX, SPF, DKIM and DMARC. Each problem comes with what to change.',
                tool_box('all', 'Check domain'))
    body += sec('The four records', '''
                <h3>MX: where mail is delivered</h3>
                <p>MX records name the servers that accept mail for the domain. No MX record, or one pointing at a host that does not exist, and incoming mail bounces.</p>
                <h3>SPF: which servers may send</h3>
                <p>An SPF record is a list of the servers allowed to send mail using the domain. Receivers compare the sending server against it.</p>
                <h3>DKIM: a signature on each message</h3>
                <p>The sending service signs every message, and publishes the public key in DNS so receivers can check the message was not altered or forged.</p>
                <h3>DMARC: what to do with failures</h3>
                <p>DMARC tells receivers what to do when a message passes neither SPF nor DKIM for your domain: deliver it anyway, put it in spam, or refuse it. It also asks them to send you reports.</p>''',
                'What each one is for.')
    body += sec('Tools', links(TOOLS[1:] + [('Record builder', 'Works out the exact records for catchall.mx forwarding at your DNS provider.', '/setup/')]),
                'One page per record type, with more detail.')
    body += sec('About these tools', '''
                <p>They are part of <a href="/">catchall.mx</a>, a free service that forwards every address at your domain to an inbox you already have. The same checks run on our own mail server all day, so we made them usable for any domain.</p>
                <p class="soft">Lookups go from our server straight to public DNS. We do not keep a history of what was looked up.</p>''')
    page('tools', 'Email DNS check: MX, SPF, DKIM and DMARC in one lookup - CatchAll.mx',
         'Free check of a domain\'s email DNS records. Looks up MX, SPF, DKIM and DMARC together and explains every problem in plain words. No sign-up.',
         body, 'tools')

    # ---- MX
    body = head(crumb, 'MX lookup',
                'See which mail servers receive email for a domain, in the order they are tried, and whether each one actually resolves.',
                tool_box('mx', 'Look up MX'))
    body += sec('Reading the result', '''
                <p>Each MX record has a number and a host name. The number is the priority: sending servers try the lowest number first and move to the next only if that one does not answer.</p>
                <p>The host name must be a name, not an IP address, and it must resolve to an address itself. The tool checks both and names the mail service when it recognises it.</p>''')
    body += sec('Common problems', '''
                <h3>Records for two different mail services</h3>
                <p>This happens when a new service is added without removing the old one. Mail then lands at whichever server answers, so some arrives and some seems to vanish. Keep one service's records.</p>
                <h3>The MX host does not exist</h3>
                <p>Usually a typo, or a trailing part of your own domain added by the DNS provider (<code>mail.example.net.yourdomain.com</code>). Some providers need a dot at the end of the host name to prevent that.</p>
                <h3>No MX record at all</h3>
                <p>Senders fall back to the domain's website address, which normally does not accept mail. If the domain should receive mail, it needs an MX record.</p>
                <h3>A change does not show yet</h3>
                <p>DNS answers are cached for as long as the record's TTL says, often an hour. This tool asks fresh each time the cache allows, but your own computer or provider may keep the old answer longer.</p>''')
    body += other_tools('/tools/mx-lookup/')
    page('tools/mx-lookup', 'MX lookup: find a domain\'s mail servers - CatchAll.mx',
         'Free MX record lookup. Shows the mail servers for any domain in priority order, checks that each one resolves, and flags records left over from another mail service.',
         body, 'tools')

    # ---- SPF
    body = head(crumb, 'SPF checker',
                'Reads a domain\'s SPF record one term at a time, says what each part allows, and counts the DNS lookups against the limit of 10.',
                tool_box('spf', 'Check SPF'))
    body += sec('How SPF works', '''
                <p>SPF is one TXT record on the domain that starts with <code>v=spf1</code>. It lists who may send mail for the domain, then ends with what to do about everyone else:</p>
                <table>
                    <tr><td><code>include:_spf.google.com</code></td><td>Allow the servers this other record allows. One per mail service you send through.</td></tr>
                    <tr><td><code>ip4:203.0.113.5</code></td><td>Allow this address.</td></tr>
                    <tr><td><code>mx</code> / <code>a</code></td><td>Allow the domain's own mail servers, or its own address.</td></tr>
                    <tr><td><code>-all</code></td><td>Reject everyone not listed.</td></tr>
                    <tr><td><code>~all</code></td><td>Treat everyone not listed as suspicious. The usual choice.</td></tr>
                </table>''')
    body += sec('Common problems', '''
                <h3>Two SPF records</h3>
                <p>A domain may have only one. With two, receivers give up and SPF fails for everything. This is the most common SPF mistake: each new service's instructions say "add this TXT record" when they should say "add this include to your existing record".</p>
                <h3>More than 10 DNS lookups</h3>
                <p>Every <code>include</code>, <code>a</code>, <code>mx</code> and <code>redirect</code> costs a lookup, and includes can contain more includes. Past 10, receivers stop and return an error. The tool follows the whole chain and gives you the real number.</p>
                <h3>+all or ?all at the end</h3>
                <p><code>+all</code> lets anyone send as your domain. <code>?all</code> says you have no opinion. Either way the record protects nothing.</p>
                <h3>SPF and forwarding</h3>
                <p>When mail is forwarded, it arrives from the forwarder's server, which is not in the original sender's SPF record. That is why forwarded mail depends on DKIM, and why <a href="/">catchall.mx</a> leaves a valid DKIM signature untouched.</p>''')
    body += other_tools('/tools/spf-checker/')
    page('tools/spf-checker', 'SPF checker: validate an SPF record and count lookups - CatchAll.mx',
         'Free SPF record checker. Explains each term of a domain\'s SPF record, follows every include to count DNS lookups against the limit of 10, and catches duplicate records.',
         body, 'tools')

    # ---- DKIM
    body = head(crumb, 'DKIM checker',
                'Finds the DKIM keys a domain publishes and checks each one is complete and long enough. Leave the selector empty and the common ones are tried for you.',
                tool_box('dkim', 'Check DKIM', selector=True))
    body += sec('What a selector is', '''
                <p>A domain can have many DKIM keys, one per sending service. Each is published under its own name, the selector, at <code>selector._domainkey.yourdomain.com</code>.</p>
                <p>DNS has no way to list them, so a checker either needs the selector or has to guess. This one tries about thirty names the well-known mail services use, such as <code>google</code>, <code>selector1</code> and <code>k1</code>.</p>
                <h3>Finding your selector</h3>
                <p>Open any email sent from the domain, choose "Show original" or "View source", and find the <code>DKIM-Signature</code> header. The value after <code>s=</code> is the selector, and <code>d=</code> is the domain it belongs to.</p>''')
    body += sec('Common problems', '''
                <h3>The key was cut short</h3>
                <p>A 2048-bit key is longer than the 255 characters some DNS forms accept in one piece. If the end is missing, signatures fail. Providers handle long values differently; some split them for you, some need a different entry mode.</p>
                <h3>Quote marks inside the value</h3>
                <p>If your provider adds quotes itself and you paste a value that already has them, the quotes become part of the key and it stops working. Paste the value without any quote marks.</p>
                <h3>A 1024-bit key</h3>
                <p>It still verifies, but 2048 bits has been the standard for years. Keys shorter than 1024 bits are ignored by the large mailbox providers.</p>
                <h3>An empty p=</h3>
                <p>That is a revoked key. It is how a service says "do not trust signatures made with this selector any more".</p>''')
    body += other_tools('/tools/dkim-checker/')
    page('tools/dkim-checker', 'DKIM checker: find and validate DKIM keys - CatchAll.mx',
         'Free DKIM record checker. Looks up a domain\'s DKIM key by selector, or tries the common selectors for you, and checks key length, truncation and stray quote marks.',
         body, 'tools')

    # ---- DMARC
    body = head(crumb, 'DMARC checker',
                'Shows a domain\'s DMARC record, what each part of it means, and whether forged mail using the domain is stopped or still delivered.',
                tool_box('dmarc', 'Check DMARC'))
    body += sec('How DMARC works', '''
                <p>DMARC is a TXT record at <code>_dmarc.yourdomain.com</code>. A message passes when SPF or DKIM passes <em>and</em> the domain that passed matches the one in the From line. For everything else, the record's policy applies:</p>
                <table>
                    <tr><td><code>p=none</code></td><td>Deliver as usual. Only collect reports.</td></tr>
                    <tr><td><code>p=quarantine</code></td><td>Put failing mail in the spam folder.</td></tr>
                    <tr><td><code>p=reject</code></td><td>Refuse failing mail.</td></tr>
                    <tr><td><code>rua=mailto:…</code></td><td>Where receivers send their daily summary reports.</td></tr>
                    <tr><td><code>sp=</code></td><td>A separate policy for subdomains.</td></tr>
                </table>
                <p>A subdomain without its own record uses the main domain's. The tool follows that and tells you which record applied.</p>''')
    body += sec('A safe way to turn it on', '''
                <ol>
                    <li>Start with <code>v=DMARC1; p=none; rua=mailto:you@yourdomain.com</code>. Nothing changes for your mail; you only start getting reports.</li>
                    <li>Read the reports for a couple of weeks. They list every server sending as your domain and whether it passed.</li>
                    <li>Fix the services that fail, usually by setting up DKIM for them.</li>
                    <li>Move to <code>p=quarantine</code>, and later <code>p=reject</code>.</li>
                </ol>
                <p class="soft">Gmail and Yahoo expect at least <code>p=none</code> from domains that send in volume, so having no record at all is the one state to avoid.</p>''')
    body += sec('Common problems', '''
                <h3>The record is on the wrong name</h3>
                <p>It belongs on <code>_dmarc</code>, not on the domain itself. Some DNS forms add the domain automatically, so typing the full name produces <code>_dmarc.example.com.example.com</code>.</p>
                <h3>Two DMARC records</h3>
                <p>With more than one, receivers ignore DMARC for the domain entirely.</p>
                <h3>No rua address</h3>
                <p>The policy still works, but you never see who is sending as your domain, which is most of what makes DMARC useful.</p>''')
    body += other_tools('/tools/dmarc-checker/')
    page('tools/dmarc-checker', 'DMARC checker: look up and explain a DMARC record - CatchAll.mx',
         'Free DMARC record checker. Finds the DMARC policy that applies to a domain or subdomain, explains each tag, and warns when forged mail would still be delivered.',
         body, 'tools')


# ------------------------------------------------------------------ provider guides

PROVIDERS = [
    dict(slug='cloudflare', name='Cloudflare', ns='end in <code>.ns.cloudflare.com</code>',
         open=['Log in to the Cloudflare dashboard and choose your domain.', 'Open <b>DNS</b>, then <b>Records</b>.', 'Click <b>Add record</b> for each record below.'],
         host='Name', apex='@', mx=[('Mail server', MX_HOST, True), ('Priority', '10', False), ('TTL', 'Auto', False)],
         notes=['Paste TXT values without quote marks. Cloudflare adds them itself, and pasted quotes end up inside the value.',
                'Leave TTL on Auto.',
                'If Cloudflare Email Routing is switched on for the domain, turn it off first (under <b>Email</b>). It manages the domain\'s MX records itself, and a domain can only have one service receiving its mail.',
                'The orange "proxied" cloud does not apply to MX or TXT records. Your website keeps working exactly as before.']),
    dict(slug='godaddy', name='GoDaddy', ns='end in <code>domaincontrol.com</code>',
         open=['Log in and open your <b>Domain Portfolio</b>.', 'Choose the domain, then <b>DNS</b>.', 'Click <b>Add New Record</b> for each record below.'],
         host='Name', apex='@', mx=[('Priority', '10', False), ('Value', MX_HOST, True)],
         notes=['The MX form has separate <b>Priority</b> and <b>Value</b> fields.',
                'If the domain has a GoDaddy email plan (Microsoft 365 or Professional Email), changing the MX records stops mail reaching those mailboxes.']),
    dict(slug='namecheap', name='Namecheap', ns='end in <code>registrar-servers.com</code>',
         open=['Log in and open <b>Domain List</b>.', 'Click <b>Manage</b> next to the domain, then the <b>Advanced DNS</b> tab.',
               'MX records live in the <b>Mail Settings</b> section of that tab. TXT records go under <b>Host Records</b>.'],
         host='Host', apex='@', mx=[('Value', MX_HOST, True), ('Priority', '10', False)],
         mx_intro='In <b>Mail Settings</b>, choose <b>Custom MX</b> from the menu, then add the record:',
         txt_intro='Under <b>Host Records</b>, click <b>Add new record</b>, choose <b>TXT Record</b>, fill it in and click <b>Save all changes</b>:',
         notes=['Choosing <b>Custom MX</b> replaces whatever mail setting was selected before, including Namecheap\'s own Email Forwarding.',
                'Nothing is saved until you click <b>Save all changes</b>.',
                'This applies when the domain uses Namecheap BasicDNS, PremiumDNS or FreeDNS. If it uses custom nameservers, the records are managed wherever those point.']),
    dict(slug='squarespace', name='Squarespace Domains', also='formerly Google Domains',
         ns='end in <code>squarespacedns.com</code> or <code>googledomains.com</code>',
         open=['Open the Squarespace domains dashboard and choose your domain.', 'Open <b>DNS</b>, then <b>DNS Settings</b>.', 'Under <b>Custom Records</b>, click <b>Add record</b> for each record below.'],
         host='Name', apex='@', mx=[('Mail Server', MX_HOST, True), ('Priority', '10', False)],
         notes=['Do not add quote marks around TXT values.',
                'If Squarespace added a mail preset (Google Workspace, Zoho or Titan), its records cannot be edited, only deleted. Delete the preset before adding the new MX record.',
                'Domains moved over from Google Domains are managed here now, with the same steps.']),
    dict(slug='porkbun', name='Porkbun', ns='end in <code>porkbun.com</code>',
         open=['Log in and open <b>Domain Management</b>.', 'Click <b>DNS</b> under your domain.', 'Use <b>Add Record</b> for each record below.'],
         host='Host', apex='', mx=[('Answer', MX_HOST, True), ('Priority', '10', False)],
         notes=['Leave the <b>Host</b> field empty for the domain itself. Do not type @.',
                'The mail server goes in <b>Answer</b>; the priority has its own field.']),
    dict(slug='ionos', name='IONOS', ns='contain <code>ui-dns</code>',
         open=['Log in and open <b>Domains &amp; SSL</b>.', 'Click the gear icon under <b>Actions</b> for your domain, then <b>DNS</b>.', 'Click <b>Add Record</b> for each record below.'],
         host='Host name', apex='@', mx=[('Points to', MX_HOST, True), ('Priority', '10', False)],
         notes=['If an existing MX record belongs to an IONOS mail product, that product has to be deactivated before the record can be removed.']),
    dict(slug='hostinger', name='Hostinger', ns='end in <code>dns-parking.com</code>',
         open=['Log in to the Hostinger dashboard and open <b>Domains</b>.', 'Click <b>Manage</b> next to your domain, then <b>DNS / Nameservers</b>.', 'Under <b>Manage DNS records</b>, add each record below.'],
         host='Name', apex='@', mx=[('Mail server (Points to)', MX_HOST, True), ('Priority', '10', False)],
         notes=['If the domain uses Hostinger Email, its MX records are already there. Delete them first; those mailboxes stop receiving once you do.']),
    dict(slug='route53', name='Amazon Route 53', short='Route 53', ns='contain <code>awsdns</code>',
         open=['Open the Route 53 console and go to <b>Hosted zones</b>.', 'Choose your domain.', 'Click <b>Create record</b> for each record below.'],
         host='Record name', apex='', mx=[('Value', '10 ' + MX_HOST, True)], txt_quoted=True,
         notes=['Leave <b>Record name</b> empty for the domain itself. Do not type @.',
                'The priority is part of the MX value: <code>10 mail.catchall.mx</code>.',
                'TXT values need double quotes around them, as written above.',
                'Route 53 keeps all values of one type on one name in a single record. If the domain already has a TXT record (an SPF record, for example), edit it and put the new value on its own line instead of creating a second record.']),
    dict(slug='ovh', name='OVHcloud', ns='end in <code>ovh.net</code>, <code>ovh.ca</code> or <code>anycast.me</code>',
         open=['Log in to the OVHcloud Manager and open <b>Web Cloud</b>.', 'Go to <b>Domains &amp; DNS</b>, then <b>Portfolio</b>, and choose your domain.', 'Open the <b>DNS zone</b> tab and click <b>Create a record</b> for each record below.'],
         host='Subdomain', apex='@', mx=[('Priority', '10', False), ('Target', MX_HOST, True)],
         notes=['The form adds the final dot to the mail server name itself; type it without one.',
                'The normal form limits a TXT value to 255 characters. That is plenty for these records, but a DKIM key is longer: if you add DKIM later, use <b>Modify zone</b> (text mode) for that one record.']),
]


def fields(rows):
    out = '<div class="fields">'
    for label, value, copy, *rest in rows:
        attr = f' data-fwd="{esc(rest[0])}"' if rest else ''
        shown = esc(value) if value else '<span style="all:unset;color:var(--faint);font-family:var(--sans)">leave empty</span>'
        btn = f'<button class="copy" data-copy="{esc(value)}">Copy</button>' if copy else ''
        out += f'<div><span>{esc(label)}</span><code{attr}>{shown}</code>{btn}</div>'
    return out + '</div>'


def build_guides():
    crumb = [('catchall.mx', '/'), ('Setup guides', '/guides/')]
    for p in PROVIDERS:
        name, short = p['name'], p.get('short', p['name'])
        also = f' ({p["also"]})' if p.get('also') else ''
        txt_value = '"catchall-forward=you@example.com"' if p.get('txt_quoted') else 'catchall-forward=you@example.com'
        txt_tpl = '"catchall-forward={a}"' if p.get('txt_quoted') else 'catchall-forward={a}'
        apex_words = f'<code>{p["apex"]}</code>' if p['apex'] else 'left empty'
        mx_rows = [('Type', 'MX', False), (p['host'], p['apex'], False)] + p['mx']
        txt_rows = [('Type', 'TXT', False), (p['host'], p['apex'], False), ('Value', txt_value, True, txt_tpl)]

        body = head(crumb, f'Email forwarding for a domain on {esc(name)}',
                    f'Send every address at your domain to the inbox you already use. It takes two DNS records at {esc(short)}{esc(also)} '
                    f'and about two minutes. Free, and there is no account to create.')

        body += sec('Before you start', f'''
                <ul>
                    <li><b>The domain's DNS is at {esc(short)}.</b> Its nameservers {p["ns"]}. If you are not sure, the <a href="/setup/">record builder</a> looks it up and detects the provider for you.</li>
                    <li><b>You know where the mail should go.</b> Any inbox you already read: Gmail, Outlook, iCloud, a work address.</li>
                    <li><b>Nothing else needs this domain's mail.</b> Forwarding replaces whatever receives it now. Mailboxes at Google Workspace, Microsoft 365 or your host stop receiving once the MX record changes.</li>
                </ul>
                <div class="tip"><b>Type your inbox address here</b> and the records below are filled in for you. It stays in your browser.
                    <div class="field-row"><input type="email" id="fwd" placeholder="you@example.com" autocomplete="email" autocapitalize="none" spellcheck="false" aria-label="Your inbox address"></div>
                </div>''')

        open_steps = ' '.join(p['open'][:-1])
        mx_intro = p.get('mx_intro', f'This tells the world that catchall.mx receives the domain\'s mail. {p["host"]} is {apex_words}, which means the domain itself.')
        txt_intro = p.get('txt_intro', 'This tells us where to send the mail. Use the address where you actually read email.')
        steps = f'''
                <ol class="steps">
                    <li><b>Open the DNS records.</b>
                        <p>{open_steps} {p["open"][-1]}</p></li>
                    <li><b>Delete the MX records that are already there.</b>
                        <p>A domain should have one mail service. If old MX records stay, some mail keeps going to the old place. Leave every other record alone; your website is not affected.</p></li>
                    <li><b>Add the MX record.</b>
                        <p>{mx_intro}</p>
                        {fields(mx_rows)}</li>
                    <li><b>Add the TXT record.</b>
                        <p>{txt_intro}</p>
                        {fields(txt_rows)}</li>
                    <li><b>Check it and confirm once.</b>
                        <p>Enter the domain below. When both records are right, a button appears that emails a confirmation link to your inbox. Click the link and forwarding starts. The confirmation exists so nobody can point a domain at your address and flood you.</p>
                        <div class="field-row"><input type="text" id="check-domain" placeholder="yourdomain.com" autocomplete="off" autocapitalize="none" spellcheck="false" aria-label="Your domain"><button class="btn" id="check-go">Check</button></div></li>
                </ol>'''
        body += sec('The steps', steps, f'What to click and type at {esc(short)}.')

        body += sec(f'Things to know at {esc(short)}', '<ul>' + ''.join(f'<li>{n}</li>' for n in p['notes']) + '</ul>'
                    + f'\n                <p class="soft">Menu names were checked against {esc(short)}\'s own help pages in November 2026. If a screen looks different, the <a href="/setup/">record builder</a> reads your domain\'s current records and tells you exactly what to add, change or delete.</p>')

        body += sec('If something is off', f'''
                <h3>The checker still shows the old records</h3>
                <p>DNS changes are usually visible within a few minutes, but an old answer can be cached for as long as the record's previous TTL, often an hour. Wait and check again before changing anything.</p>
                <h3>The confirmation email did not arrive</h3>
                <p>Look in the spam folder first. The link is valid for 24 hours, and the checker can send it again after ten minutes.</p>
                <h3>Mail from some senders is missing</h3>
                <p>Look for leftover MX records from a previous mail service; the <a href="/tools/mx-lookup/">MX lookup</a> shows all of them. Mail that arrives before you confirm is held for 24 hours and delivered once you do.</p>
                <h3>You want to stop</h3>
                <p>Delete the two records. Nothing else needs undoing, and there is no account to close.</p>''')

        body += sec('After it works', '''
                <h3>Different addresses to different inboxes</h3>
                <p>More TXT records can send single addresses elsewhere, block addresses that get spam, or accept only a list you choose. The <a href="/setup/">record builder</a> writes them for you.</p>
                <h3>Sign forwarded mail as your domain</h3>
                <p>Adding one DKIM record lets forwarded mail be signed by your own domain, which helps it reach the inbox. It is optional, and the builder covers it too.</p>
                <h3>Check the rest of your email DNS</h3>
                <p>The <a href="/tools/">DNS check</a> looks at MX, SPF, DKIM and DMARC together.</p>''', 'Optional extras.')

        others = [(q['name'], f'Email forwarding for a domain on {q.get("short", q["name"])}.', f'/guides/{q["slug"]}/')
                  for q in PROVIDERS if q['slug'] != p['slug']]
        body += sec('Other providers', links(others))
        page(f'guides/{p["slug"]}', f'Free email forwarding for a {short} domain - CatchAll.mx',
             f'Step-by-step: forward every address at a domain on {name} to Gmail, Outlook or any inbox. Two DNS records, the exact fields to fill in at {short}, free, no account.',
             body, 'guides')

    # ---- index
    body = head(crumb[:1], 'Setup guides by DNS provider',
                'The same two records everywhere, but every provider names its menus and fields differently. Pick yours for the exact clicks.')
    body += sec('Providers', links([(p['name'] + (f' ({p["also"]})' if p.get('also') else ''),
                                     f'MX: {p["host"]} {"@" if p["apex"] else "empty"}, {p["mx"][0][0] if p["mx"][0][0] != "Priority" else p["mx"][1][0]} mail.catchall.mx.',
                                     f'/guides/{p["slug"]}/') for p in PROVIDERS]))
    body += sec('Somewhere else?', f'''
                <p>Any provider that lets you add MX and TXT records works. The records are:</p>
                <div class="rec"><span class="t">MX</span><span class="v">{MX_HOST} &nbsp;priority 10</span><button class="copy" data-copy="{MX_HOST}">Copy</button></div>
                <div class="rec"><span class="t">TXT</span><span class="v">catchall-forward=you@example.com</span><button class="copy" data-copy="catchall-forward=you@example.com">Copy</button></div>
                <p style="margin-top:16px">Both go on the domain itself, which most providers write as <code>@</code>. The <a href="/setup/">record builder</a> reads what your domain has now and lists what to add, change or delete. It also knows DigitalOcean, Gandi and Name.com.</p>''',
                'The general version.')
    page('guides', 'Email forwarding setup guides by DNS provider - CatchAll.mx',
         'How to set up free catch-all email forwarding at Cloudflare, GoDaddy, Namecheap, Squarespace, Porkbun, IONOS, Hostinger, Route 53 and OVHcloud: the exact menus and fields.',
         body, 'guides')


def build_sitemap():
    today = date.today().isoformat()
    urls = [''] + ['setup/'] + [p + '/' for p in written]
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for u in urls:
        xml += f'  <url><loc>{SITE}/{u}</loc><lastmod>{today}</lastmod></url>\n'
    xml += '</urlset>\n'
    with open(os.path.join(ROOT, 'sitemap.xml'), 'w') as f:
        f.write(xml)
    with open(os.path.join(ROOT, 'robots.txt'), 'w') as f:
        f.write(f'User-agent: *\nDisallow: /api/\nDisallow: /verify/\nDisallow: /quarantine\n\nSitemap: {SITE}/sitemap.xml\n')


if __name__ == '__main__':
    build_tools()
    build_guides()
    build_sitemap()
    print(f'{len(written)} pages written:', ', '.join(written))
