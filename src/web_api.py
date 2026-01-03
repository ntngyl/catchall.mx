#!/usr/bin/env python3
"""
CatchAll.mx - Web API with DKIM Support
Handles DNS checking, verification, and DKIM management
"""

from flask import Flask, request, jsonify
import dns.resolver
import redis
from verification import verify_domain_token
from dkim_manager import generate_dkim_key, verify_dkim_dns, is_dkim_enabled, get_dns_record
import logging

logging.basicConfig(
    filename='/var/log/catchall/verification.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)
r = redis.Redis(decode_responses=True)

@app.route('/api/check-dns')
def check_dns():
    """Check domain DNS configuration"""

    domain = request.args.get('domain', '').lower().strip()

    if not domain:
        return jsonify({'error': 'Domain parameter required'}), 400

    result = {
        'domain': domain,
        'mx_record': {'found': False},
        'txt_records': {},
        'dkim': {'enabled': False},
        'status': 'incomplete'
    }

    # Check MX record
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip('.')
            if mx_host == 'mail.catchall.mx':
                result['mx_record'] = {
                    'found': True,
                    'value': mx_host,
                    'priority': mx.preference,
                    'valid': True
                }
                break
    except:
        result['mx_record'] = {'found': False, 'error': 'No MX record found'}

    # Check TXT records
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for rdata in txt_records:
            txt = str(rdata).strip('"')

            if txt.startswith('catchall-forward='):
                value = txt.split('=', 1)[1]
                result['txt_records']['catchall-forward'] = {
                    'found': True,
                    'value': value,
                    'valid': '@' in value
                }
            elif txt.startswith('catchall-limit='):
                value = txt.split('=', 1)[1]
                result['txt_records']['catchall-limit'] = {
                    'found': True,
                    'value': value,
                    'valid': value.isdigit()
                }
            elif txt.startswith('catchall-spam='):
                value = txt.split('=', 1)[1]
                result['txt_records']['catchall-spam'] = {
                    'found': True,
                    'value': value,
                    'valid': value in ['strict', 'moderate', 'off']
                }
    except:
        pass

    # Set defaults for optional records
    if 'catchall-limit' not in result['txt_records']:
        result['txt_records']['catchall-limit'] = {
            'found': False,
            'default': '50'
        }

    if 'catchall-spam' not in result['txt_records']:
        result['txt_records']['catchall-spam'] = {
            'found': False,
            'default': 'moderate'
        }

    # Check DKIM status
    result['dkim']['enabled'] = is_dkim_enabled(domain)

    # Determine status
    mx_ok = result['mx_record'].get('valid', False)
    forward_ok = result['txt_records'].get('catchall-forward', {}).get('valid', False)

    if mx_ok and forward_ok:
        result['status'] = 'ready'
        result['message'] = 'Your domain is configured correctly!'
        if result['dkim']['enabled']:
            result['message'] += ' DKIM signing is enabled.'
    elif forward_ok:
        result['status'] = 'partial'
        result['message'] = 'Add MX record: mail.catchall.mx (priority 10)'
    elif mx_ok:
        result['status'] = 'partial'
        result['message'] = 'Add TXT record: catchall-forward=your@email.com'
    else:
        result['status'] = 'incomplete'
        result['message'] = 'DNS records not configured'

    return jsonify(result)

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

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
