#!/usr/bin/env python3
"""
CatchAll.mx - Web API
Handles DNS checking and verification endpoints
"""

from flask import Flask, request, jsonify
import dns.resolver
import redis
import logging
import os

# Load environment
from dotenv import load_dotenv
load_dotenv('/etc/catchall.env')

from verification import verify_domain_token

logging.basicConfig(
    filename='/var/log/catchall/web_api.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)
r = redis.Redis(
    host=os.getenv('REDIS_HOST', 'localhost'),
    port=int(os.getenv('REDIS_PORT', 6379)),
    decode_responses=True
)

DOMAIN = os.getenv('DOMAIN', 'catchall.mx')

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
        'status': 'incomplete'
    }

    # Check MX record
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip('.')
            if mx_host == f'mail.{DOMAIN}':
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

    # Determine status
    mx_ok = result['mx_record'].get('valid', False)
    forward_ok = result['txt_records'].get('catchall-forward', {}).get('valid', False)

    if mx_ok and forward_ok:
        result['status'] = 'ready'
        result['message'] = 'Your domain is configured correctly!'
    elif forward_ok:
        result['status'] = 'partial'
        result['message'] = f'Add MX record: mail.{DOMAIN} (priority 10)'
    elif mx_ok:
        result['status'] = 'partial'
        result['message'] = 'Add TXT record: catchall-forward=your@email.com'
    else:
        result['status'] = 'incomplete'
        result['message'] = 'DNS records not configured'

    return jsonify(result)

@app.route('/verify/<domain>')
def verify_route(domain):
    """Handle verification link clicks"""

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
    <title>{title} - {DOMAIN}</title>
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
        <a href="https://{DOMAIN}" class="home-link">← Back to {DOMAIN}</a>
    </div>
</body>
</html>
"""

    return html

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
