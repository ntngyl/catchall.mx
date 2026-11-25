#!/usr/bin/env python3
"""
CatchAll.mx - Web API with DKIM Support
Handles DNS checking, verification, and DKIM management
"""

from flask import Flask, request, jsonify, render_template_string
import dns.resolver
import redis
import requests
import os
from verification import verify_domain_token
from dkim_manager import generate_dkim_key, verify_dkim_dns, is_dkim_enabled, get_dns_record
from quarantine_manager import get_quarantined_emails, release_email, delete_email, get_email_content
import logging

logging.basicConfig(
    filename='/var/log/catchall/verification.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)


@app.after_request
def add_shared_stylesheet(response):
    """Give every server-rendered page the site look (served by nginx from /app.css)"""
    try:
        if response.mimetype == 'text/html' and not response.direct_passthrough:
            html = response.get_data(as_text=True)
            if '</head>' in html and '/app.css' not in html:
                response.set_data(html.replace(
                    '</head>', '<link rel="stylesheet" href="/app.css?v=1"></head>', 1))
    except Exception:
        pass
    return response
r = redis.Redis(decode_responses=True)

@app.route('/api/check-dns')
def check_dns():
    """Check domain DNS configuration and name the specific mistake, if any"""
    from dns_check import check_domain
    from abuse import is_abuse_blocked

    raw = request.args.get('domain', '')
    if not raw.strip():
        return jsonify({'error': 'Domain parameter required'}), 400

    return jsonify(check_domain(raw, is_dkim_enabled=is_dkim_enabled,
                                is_abuse_blocked=is_abuse_blocked))

@app.route('/api/dkim')
def api_dkim():
    """DKIM record for a domain, for the record builder.

    Returns the TXT record the domain should publish and what it publishes
    now. generate=1 creates the key if the domain has none yet. When the
    published record matches, signing is switched on.
    """
    from dns_check import clean_domain, DOMAIN_RE
    from dkim_manager import DKIM_SELECTOR

    domain = clean_domain(request.args.get('domain', ''))
    if not domain or len(domain) > 253 or not DOMAIN_RE.fullmatch(domain):
        return jsonify({'error': 'That does not look like a domain name.'}), 400

    host = f"{DKIM_SELECTOR}._domainkey"
    published = []
    try:
        res = dns.resolver.Resolver()
        res.lifetime = 6
        for rdata in res.resolve(f"{host}.{domain}", 'TXT'):
            published.append(b''.join(rdata.strings).decode('utf-8', 'replace'))
    except Exception:
        pass

    ok, info = get_dns_record(domain)
    if not ok and request.args.get('generate') == '1':
        ok, info = generate_dkim_key(domain)

    matches, problem = False, None
    if ok and published:
        matches, message = verify_dkim_dns(domain)
        if not matches:
            problem = message

    return jsonify({
        'domain': domain,
        'host': host,
        'value': info['value'] if ok else None,
        'published': published,
        'matches': bool(matches),
        'enabled': bool(is_dkim_enabled(domain)),
        'problem': problem,
    })

@app.route('/dkim/setup')
def dkim_setup():
    """Generate DKIM key and show DNS record to add"""

    domain = request.args.get('domain', '').lower().strip()

    if not domain:
        return """
<!DOCTYPE html>
<html>
<head>
    <title>DKIM Setup - CatchAll.mx</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        input { padding: 12px; font-size: 16px; width: 300px; border: 2px solid #ddd; border-radius: 6px; }
        button { padding: 12px 24px; background: #667eea; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
        button:hover { background: #5a67d8; }
    </style>
</head>
<body>
    <h1>🔐 DKIM Setup</h1>
    <p>Enter your domain to generate a DKIM key:</p>
    <form action="/dkim/setup" method="get">
        <input type="text" name="domain" placeholder="example.com" required>
        <button type="submit">Generate DKIM Key</button>
    </form>
    <p style="margin-top: 30px; color: #666;">
        <a href="https://catchall.mx">← Back to CatchAll.mx</a>
    </p>
</body>
</html>
"""

    # Generate DKIM key
    success, result = generate_dkim_key(domain)

    if not success:
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>DKIM Setup Error - CatchAll.mx</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
        .error {{ background: #fee; border: 1px solid #fcc; padding: 20px; border-radius: 8px; color: #c00; }}
    </style>
</head>
<body>
    <h1>❌ DKIM Setup Error</h1>
    <div class="error">
        <p>{result}</p>
    </div>
    <p><a href="/dkim/setup">← Try again</a></p>
</body>
</html>
""", 500

    # Show DNS record to add
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>DKIM Setup - {domain} - CatchAll.mx</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
        .success {{ background: #e8f5e9; border: 1px solid #a5d6a7; padding: 20px; border-radius: 8px; color: #2e7d32; margin-bottom: 30px; }}
        .dns-record {{ background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .dns-record .field {{ position: relative; margin: 15px 0; }}
        .dns-record .label {{ font-weight: bold; color: #333; margin-bottom: 5px; }}
        .dns-record code {{ display: block; background: #fff; padding: 15px; padding-right: 80px; border-radius: 4px; word-break: break-all; font-size: 13px; border: 1px solid #ddd; }}
        .copy-btn {{ position: absolute; right: 8px; top: 50%; transform: translateY(-50%); padding: 6px 12px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }}
        .copy-btn:hover {{ background: #5a67d8; }}
        .copy-btn.copied {{ background: #10b981; }}
        .verify-btn {{ display: inline-block; padding: 12px 24px; background: #667eea; color: white; text-decoration: none; border-radius: 6px; margin-top: 20px; }}
        .verify-btn:hover {{ background: #5a67d8; }}
        .steps {{ background: #fff3e0; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .steps ol {{ margin: 0; padding-left: 20px; }}
        .steps li {{ margin: 10px 0; }}
    </style>
</head>
<body>
    <h1>🔐 DKIM Key Generated</h1>

    <div class="success">
        <strong>✅ DKIM key generated for {domain}</strong>
    </div>

    <div class="steps">
        <h3>📋 Steps to Enable DKIM:</h3>
        <ol>
            <li>Add the DNS record below to your domain</li>
            <li>Wait for DNS propagation (usually 5-15 minutes)</li>
            <li>Click "Verify DKIM" to activate signing</li>
        </ol>
    </div>

    <div class="dns-record">
        <div class="field">
            <div class="label">Type:</div>
            <code>TXT</code>
        </div>

        <div class="field" style="position: relative;">
            <div class="label">Host / Name:</div>
            <code id="host-value">{result['host']}</code>
            <button class="copy-btn" onclick="copyToClipboard('host-value', this)">Copy</button>
        </div>

        <div class="field" style="position: relative;">
            <div class="label">Value:</div>
            <code id="dkim-value">{result['value']}</code>
            <button class="copy-btn" onclick="copyToClipboard('dkim-value', this)">Copy</button>
        </div>
    </div>

    <p style="color: #666; font-size: 14px;">
        <strong>Note:</strong> The full DNS record will be: <code>{result['full_host']}</code>
    </p>

    <a href="/dkim/verify?domain={domain}" class="verify-btn">Verify DKIM →</a>

    <p style="margin-top: 30px; color: #666;">
        <a href="https://catchall.mx">← Back to CatchAll.mx</a>
    </p>

    <script>
    function copyToClipboard(elementId, btn) {{
        const text = document.getElementById(elementId).innerText;
        navigator.clipboard.writeText(text).then(() => {{
            btn.innerText = 'Copied!';
            btn.classList.add('copied');
            setTimeout(() => {{
                btn.innerText = 'Copy';
                btn.classList.remove('copied');
            }}, 2000);
        }});
    }}
    </script>
</body>
</html>
"""

@app.route('/dkim/verify')
def dkim_verify():
    """Verify DKIM DNS record and enable signing"""

    domain = request.args.get('domain', '').lower().strip()

    if not domain:
        return """
<!DOCTYPE html>
<html>
<head>
    <title>DKIM Verify - CatchAll.mx</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        input { padding: 12px; font-size: 16px; width: 300px; border: 2px solid #ddd; border-radius: 6px; }
        button { padding: 12px 24px; background: #667eea; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
    </style>
</head>
<body>
    <h1>🔍 Verify DKIM</h1>
    <form action="/dkim/verify" method="get">
        <input type="text" name="domain" placeholder="example.com" required>
        <button type="submit">Verify DKIM</button>
    </form>
</body>
</html>
"""

    success, message = verify_dkim_dns(domain)

    if success:
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>DKIM Verified - {domain} - CatchAll.mx</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }}
        .success {{ background: #e8f5e9; border: 1px solid #a5d6a7; padding: 40px; border-radius: 12px; }}
        .icon {{ font-size: 64px; margin-bottom: 20px; }}
        h1 {{ color: #2e7d32; }}
        .home-link {{ display: inline-block; margin-top: 30px; padding: 12px 24px; background: #667eea; color: white; text-decoration: none; border-radius: 6px; }}
    </style>
</head>
<body>
    <div class="success">
        <div class="icon">✅</div>
        <h1>DKIM Enabled!</h1>
        <p>{message}</p>
        <p style="margin-top: 20px; color: #666;">
            All emails forwarded from <strong>*@{domain}</strong> will now be signed with DKIM.
        </p>
    </div>
    <a href="https://catchall.mx" class="home-link">← Back to CatchAll.mx</a>
</body>
</html>
"""
    else:
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>DKIM Verification Failed - CatchAll.mx</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }}
        .error {{ background: #ffebee; border: 1px solid #ffcdd2; padding: 40px; border-radius: 12px; }}
        .icon {{ font-size: 64px; margin-bottom: 20px; }}
        h1 {{ color: #c62828; }}
        .retry-link {{ display: inline-block; margin-top: 20px; padding: 12px 24px; background: #667eea; color: white; text-decoration: none; border-radius: 6px; }}
        .setup-link {{ display: inline-block; margin-top: 10px; color: #667eea; }}
    </style>
</head>
<body>
    <div class="error">
        <div class="icon">❌</div>
        <h1>Verification Failed</h1>
        <p>{message}</p>
        <p style="margin-top: 20px; color: #666;">
            DNS propagation can take up to 24 hours. Please try again later.
        </p>
    </div>
    <a href="/dkim/verify?domain={domain}" class="retry-link">Try Again</a>
    <br>
    <a href="/dkim/setup?domain={domain}" class="setup-link">View DNS Record</a>
</body>
</html>
"""

@app.route('/api/dkim-status')
def dkim_status():
    """Check DKIM status for a domain"""

    domain = request.args.get('domain', '').lower().strip()

    if not domain:
        return jsonify({'error': 'Domain parameter required'}), 400

    enabled = is_dkim_enabled(domain)

    # Check if key exists
    success, record = get_dns_record(domain)

    return jsonify({
        'domain': domain,
        'enabled': enabled,
        'key_generated': success,
        'dns_record': record if success else None
    })

@app.route('/verify/<domain>')
def verify_route(domain):
    """Handle verification link clicks with accept/block"""

    token = request.args.get('token', '')
    action = request.args.get('action', 'accept')

    success, message = verify_domain_token(domain, token, action)

    if action == 'block':
        status_class = 'blocked' if success else 'error'
        emoji = '🚫' if success else '❌'
        title = 'Domain Blocked' if success else 'Verification Failed'
        bg_color = '#f44336' if success else '#666'
    else:
        status_class = 'success' if success else 'error'
        emoji = '✅' if success else '❌'
        title = 'Verification Successful!' if success else 'Verification Failed'
        bg_color = '#4CAF50' if success else '#666'

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - CatchAll.mx</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 0 auto;
            padding: 40px 20px;
            text-align: center;
        }}
        .result-box {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.1);
            padding: 40px;
            margin-top: 40px;
        }}
        .icon {{
            font-size: 64px;
            margin-bottom: 20px;
        }}
        .title {{
            color: {bg_color};
            font-size: 28px;
            font-weight: bold;
            margin-bottom: 20px;
        }}
        .message {{
            font-size: 16px;
            color: #666;
            line-height: 1.6;
            margin-bottom: 30px;
        }}
        .home-link {{
            display: inline-block;
            margin-top: 20px;
            color: #2196F3;
            text-decoration: none;
            padding: 12px 24px;
            border: 2px solid #2196F3;
            border-radius: 6px;
            transition: all 0.3s;
            font-weight: 600;
        }}
        .home-link:hover {{
            background: #2196F3;
            color: white;
        }}
    </style>
</head>
<body>
    <div class="result-box">
        <div class="icon">{emoji}</div>
        <div class="title">{title}</div>
        <div class="message">{message}</div>
        <a href="https://catchall.mx" class="home-link">← Back to CatchAll.mx</a>
    </div>
</body>
</html>
"""

    return html

@app.route('/report', methods=['GET', 'POST'])
def report_abuse():
    """
    Abuse reporting endpoint.
    GET: Show reporting form.
    POST: Submit abuse report and auto-block domain.
    """
    if request.method == 'GET':
        domain = request.args.get('domain', '')
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Report Abuse - CatchAll.mx</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
        input, textarea, select {{ padding: 12px; font-size: 16px; width: 100%; border: 2px solid #ddd; border-radius: 6px; margin-bottom: 15px; box-sizing: border-box; }}
        button {{ padding: 12px 24px; background: #667eea; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }}
        button:hover {{ background: #5a67d8; }}
        .notice {{ background: #fff3e0; padding: 20px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #ff9800; }}
    </style>
</head>
<body>
    <h1>Report Abuse</h1>
    <div class="notice">
        <p><strong>Use this form to report spam or abuse from a domain using CatchAll.mx.</strong></p>
        <p>We will investigate and block the domain if violations are confirmed.</p>
    </div>
    <form method="post" action="/report">
        <label>Domain using CatchAll.mx:</label>
        <input type="text" name="domain" placeholder="example.com" value="{domain}" required>

        <label>Your email (optional):</label>
        <input type="email" name="reporter" placeholder="you@example.com">

        <label>Type of abuse:</label>
        <select name="type" required>
            <option value="spam">Spam / Unsolicited email</option>
            <option value="phishing">Phishing / Fraud</option>
            <option value="spoofing">Email spoofing</option>
            <option value="other">Other</option>
        </select>

        <label>Details:</label>
        <textarea name="details" rows="4" placeholder="Describe the abuse..."></textarea>

        <button type="submit">Submit Report</button>
    </form>
    <p style="margin-top: 30px; color: #666;">
        <a href="https://catchall.mx">← Back to CatchAll.mx</a>
    </p>
</body>
</html>
"""

    # POST handler
    domain = request.form.get('domain', '').lower().strip()
    reporter = request.form.get('reporter', '').strip()
    abuse_type = request.form.get('type', 'other')
    details = request.form.get('details', '')

    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    # Validate domain is actually using our service
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_hosts = [str(mx.exchange).rstrip('.') for mx in answers]
        if 'mail.catchall.mx' not in mx_hosts:
            return f"""
<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:50px auto;padding:20px;">
<h1 style="color:#c62828;">Domain Not Using CatchAll.mx</h1>
<p>The domain <strong>{domain}</strong> does not point its MX record to mail.catchall.mx.</p>
<p>If this is incorrect, please try again.</p>
<a href="/report">← Back</a>
</body></html>
""", 400
    except Exception as e:
        return f"""
<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:50px auto;padding:20px;">
<h1 style="color:#c62828;">DNS Lookup Failed</h1>
<p>Could not verify MX records for <strong>{domain}</strong>.</p>
<a href="/report">← Back</a>
</body></html>
""", 400

    # Block the domain in Redis
    block_key = f"abuse_block:{domain}"
    r.setex(block_key, 30 * 86400, f"{abuse_type}:{reporter}:{details[:200]}")

    # Also mark as bounce block for consistency
    r.setex(f"bounce_block:{domain}", 30 * 86400, f"abuse_report:{abuse_type}")

    logging.warning(f"ABUSE REPORT: {domain} | type={abuse_type} | reporter={reporter} | details={details[:200]}")

    return f"""
<!DOCTYPE html>
<html>
<head><title>Report Submitted - CatchAll.mx</title>
<meta charset="UTF-8">
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }}
    .success {{ background: #e8f5e9; border: 1px solid #a5d6a7; padding: 40px; border-radius: 12px; }}
    h1 {{ color: #2e7d32; }}
</style>
</head>
<body>
    <div class="success">
        <h1>Report Submitted</h1>
        <p>Thank you. We have received your report for <strong>{domain}</strong>.</p>
        <p>The domain has been temporarily blocked pending investigation.</p>
        <a href="https://catchall.mx" style="display:inline-block;margin-top:20px;padding:12px 24px;background:#667eea;color:white;text-decoration:none;border-radius:6px;">← Back to CatchAll.mx</a>
    </div>
</body>
</html>
"""


@app.route('/quarantine')
def quarantine_dashboard():
    """
    Simple quarantine review dashboard.
    Shows quarantined emails with release/delete actions.
    """
    domain_filter = request.args.get('domain', '')
    emails = get_quarantined_emails(domain_filter if domain_filter else None)

    rows = ""
    for email in emails:
        ts = int(email.get('timestamp', 0))
        time_str = __import__('datetime').datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')
        rows += f"""
        <tr>
            <td>{email.get('domain', '')}</td>
            <td>{email.get('reason', '')}</td>
            <td>{email.get('score', '0')}</td>
            <td>{time_str}</td>
            <td>{email.get('status', 'pending')}</td>
            <td>
                <a href="/quarantine/view?id={email['email_id']}" target="_blank">View</a>
                <form method="post" action="/quarantine/release" style="display:inline;">
                    <input type="hidden" name="id" value="{email['email_id']}">
                    <button type="submit" style="padding:4px 8px;font-size:12px;">Release</button>
                </form>
                <form method="post" action="/quarantine/delete" style="display:inline;">
                    <input type="hidden" name="id" value="{email['email_id']}">
                    <button type="submit" style="padding:4px 8px;font-size:12px;background:#c62828;">Delete</button>
                </form>
            </td>
        </tr>
        """

    if not rows:
        rows = '<tr><td colspan="6" style="text-align:center;padding:20px;color:#666;">No quarantined emails.</td></tr>'

    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Quarantine - CatchAll.mx</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f5f5f5; font-weight: 600; }}
        tr:hover {{ background: #f9f9f9; }}
        button {{ cursor: pointer; border: none; border-radius: 4px; background: #667eea; color: white; }}
        button:hover {{ background: #5a67d8; }}
        .filter {{ margin-bottom: 20px; }}
        .filter input {{ padding: 8px; border: 2px solid #ddd; border-radius: 4px; }}
        .filter button {{ padding: 8px 16px; background: #667eea; color: white; border: none; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>Quarantine Dashboard</h1>
    <div class="filter">
        <form method="get" action="/quarantine">
            <input type="text" name="domain" placeholder="Filter by domain..." value="{domain_filter}">
            <button type="submit">Filter</button>
            <a href="/quarantine" style="margin-left:10px;color:#667eea;">Clear</a>
        </form>
    </div>
    <table>
        <thead>
            <tr>
                <th>Domain</th>
                <th>Reason</th>
                <th>Score</th>
                <th>Time</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
    <p style="margin-top:30px;color:#666;">
        <a href="https://catchall.mx">← Back to CatchAll.mx</a>
    </p>
</body>
</html>
"""


@app.route('/quarantine/view')
def quarantine_view():
    """View raw content of a quarantined email."""
    email_id = request.args.get('id', '')
    content = get_email_content(email_id)
    if content is None:
        return "Email not found", 404

    # Escape HTML for safe display
    import html
    safe_content = html.escape(content)

    return f"""
<!DOCTYPE html>
<html>
<head><title>Quarantined Email - CatchAll.mx</title>
<meta charset="UTF-8">
<style>
    body {{ font-family: monospace; max-width: 900px; margin: 20px auto; padding: 20px; background: #1e1e1e; color: #d4d4d4; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #252526; padding: 20px; border-radius: 8px; overflow-x: auto; }}
    a {{ color: #667eea; }}
</style>
</head>
<body>
    <h2>Quarantined Email</h2>
    <pre>{safe_content}</pre>
    <p><a href="/quarantine">← Back to Quarantine</a></p>
</body>
</html>
"""


@app.route('/quarantine/release', methods=['POST'])
def quarantine_release():
    """Release a quarantined email."""
    email_id = request.form.get('id', '')
    if not email_id:
        return jsonify({'error': 'Email ID required'}), 400

    # Try to get forward address from the quarantined email headers
    content = get_email_content(email_id)
    forward_to = None
    if content:
        for line in content.split('\n'):
            if line.lower().startswith('x-original-to:') or line.lower().startswith('to:'):
                forward_to = line.split(':', 1)[1].strip()
                break

    if not forward_to or '@' not in forward_to:
        # Try to get from DNS
        meta = r.hgetall(f"quarantine:meta:{email_id}")
        if meta:
            domain = meta.get('domain', '')
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if txt.startswith('catchall-forward='):
                        forward_to = txt.split('=', 1)[1]
                        break
            except:
                pass

    if not forward_to:
        return jsonify({'error': 'Could not determine forward address'}), 400

    success, message = release_email(email_id, forward_to)
    if success:
        return f"""
<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:50px auto;padding:20px;">
<h1 style="color:#2e7d32;">Released</h1>
<p>Email released and forwarded to <strong>{forward_to}</strong>.</p>
<a href="/quarantine">← Back</a>
</body></html>
"""
    else:
        return f"""
<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:50px auto;padding:20px;">
<h1 style="color:#c62828;">Failed</h1>
<p>Could not release email: {message}</p>
<a href="/quarantine">← Back</a>
</body></html>
""", 500


@app.route('/quarantine/delete', methods=['POST'])
def quarantine_delete():
    """Delete a quarantined email permanently."""
    email_id = request.form.get('id', '')
    if not email_id:
        return jsonify({'error': 'Email ID required'}), 400

    success, message = delete_email(email_id)
    if success:
        return f"""
<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:50px auto;padding:20px;">
<h1 style="color:#2e7d32;">Deleted</h1>
<p>Email permanently deleted.</p>
<a href="/quarantine">← Back</a>
</body></html>
"""
    else:
        return f"""
<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:50px auto;padding:20px;">
<h1 style="color:#c62828;">Failed</h1>
<p>Could not delete email: {message}</p>
<a href="/quarantine">← Back</a>
</body></html>
""", 500


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
