# CatchAll.mx

**Simple, privacy-focused email forwarding for developers.**

Forward all emails from `*@yourdomain.com` to your inbox with just 2 DNS records. No accounts, no dashboards, no BS.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## How It Works

```
Email arrives → DNS lookup → Forward to you → Delete immediately
```

We **don't store** your emails. They pass through and are gone forever.

### What We Store
- Domain name (e.g., `example.com`)
- Verified status (yes/no)
- Daily email count

That's it. No email content. No metadata. No tracking.

## Quick Start (Using catchall.mx)

### 1. Add MX Record
```
Type: MX
Host: @
Value: mail.catchall.mx
Priority: 10
```

### 2. Add TXT Record
```
Type: TXT
Host: @
Value: catchall-forward=your@email.com
```

### 3. Send a Test Email
Send an email to `anything@yourdomain.com`. You'll receive a verification email - click "Accept" and you're done!

## Self-Hosting

Want to run your own instance? Here's how.

### Requirements
- Ubuntu 22.04+ (or similar)
- Postfix
- Redis
- Python 3.10+
- Nginx (for web interface)

### Installation

```bash
# Clone the repo
git clone https://github.com/ntngyl/catchall.mx.git
cd catchall.mx

# Install dependencies
apt install postfix redis-server python3-pip nginx certbot
pip3 install -r requirements.txt

# Copy source files
cp -r src/* /opt/catchall/
chmod +x /opt/catchall/*.py

# Create directories
mkdir -p /var/spool/catchall/queue
mkdir -p /var/log/catchall
chown -R nobody:nogroup /var/spool/catchall
chown -R nobody:nogroup /var/log/catchall

# Configure environment
cp config/catchall.env.example /etc/catchall.env
nano /etc/catchall.env  # Add your SMTP credentials

# Install systemd services
cp config/systemd/*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable catchall-policy catchall-web
systemctl start catchall-policy catchall-web

# Configure Postfix
cat config/postfix/main.cf.append >> /etc/postfix/main.cf
cp config/postfix/master.cf.append /etc/postfix/master.cf.d/catchall.conf
systemctl restart postfix

# Configure Nginx
cp config/nginx/catchall.conf /etc/nginx/sites-available/
ln -s /etc/nginx/sites-available/catchall.conf /etc/nginx/sites-enabled/
certbot --nginx -d yourdomain.com
systemctl restart nginx
```

### Configuration

#### Environment Variables (`/etc/catchall.env`)

```bash
# SMTP for sending verification emails
SMTP_HOST=smtp.your-provider.com
SMTP_PORT=587
SMTP_USERNAME=your@email.com
SMTP_PASSWORD=your-password
FROM_EMAIL=verify@yourdomain.com
FROM_NAME=YourDomain

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Domain
DOMAIN=yourdomain.com
```

#### Optional DNS Records

```
catchall-limit=100       # Max emails per day (default: 50)
catchall-size=10         # Max email size in MB (default: 5)
catchall-spam=strict     # Spam filtering: strict, moderate, off (default: moderate)
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         INTERNET                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     MX: mail.catchall.mx                        │
│                         (Postfix)                               │
│  ┌─────────────────┐    ┌──────────────────┐                   │
│  │ Policy Daemon   │◄───│ smtpd_policy     │                   │
│  │ (port 10032)    │    │ check            │                   │
│  └────────┬────────┘    └──────────────────┘                   │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │ DNS TXT Lookup  │  catchall-forward=user@gmail.com          │
│  └────────┬────────┘                                           │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐    ┌──────────────────┐                   │
│  │ Rate Limiter    │───►│ Redis            │                   │
│  │ (per domain)    │    │ (counters/queue) │                   │
│  └────────┬────────┘    └──────────────────┘                   │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────────────────────────────┐                   │
│  │            Verification Check            │                   │
│  │  ┌─────────────┐    ┌─────────────────┐ │                   │
│  │  │ Not Verified│    │ Verified        │ │                   │
│  │  │ → Queue     │    │ → Forward Now   │ │                   │
│  │  │ → Send Link │    │ → Delete        │ │                   │
│  │  └─────────────┘    └─────────────────┘ │                   │
│  └─────────────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────────┘
```

## Files

| File | Purpose |
|------|---------|
| `forward_email.py` | Main email handler (called by Postfix) |
| `policy_daemon.py` | Postfix policy service (rate limits, DNS check) |
| `verification.py` | Verification email sender |
| `queue_manager.py` | Email queue during verification |
| `web_api.py` | Web API (DNS checker, verification links) |
| `forwarder.py` | SMTP forwarding module |

## Privacy & Security

### What happens to your emails:
1. Email arrives at our server
2. We read DNS TXT record to get forward address
3. We forward the email to your address
4. We **delete the email immediately**

### What we store:
- Domain name
- Verified status (yes/no)
- Daily email count (resets at midnight)
- Blocked domains (if you click "Block")

### What we DON'T store:
- Email content
- Email headers
- Sender addresses
- Recipient addresses
- Timestamps
- Attachments
- Anything else

### Verification queue:
- First email waits for verification (max 24 hours)
- Once verified → forwarded → deleted
- Unverified emails auto-delete after 24 hours

## API

### Check DNS Configuration
```bash
curl "https://catchall.mx/api/check-dns?domain=example.com"
```

Response:
```json
{
  "domain": "example.com",
  "mx_record": {
    "found": true,
    "value": "mail.catchall.mx",
    "valid": true
  },
  "txt_records": {
    "catchall-forward": {
      "found": true,
      "value": "you@gmail.com",
      "valid": true
    }
  },
  "status": "ready",
  "message": "Your domain is configured correctly!"
}
```

## Contributing

Contributions welcome! Please:

1. Fork the repo
2. Create a feature branch
3. Make your changes
4. Submit a PR

## License

MIT License - see [LICENSE](LICENSE)

## Support

- GitHub Issues: [github.com/ntngyl/catchall.mx/issues](https://github.com/ntngyl/catchall.mx/issues)
- Email: nitin@mrig.in

---

Made with ❤️ for developers who just want their emails forwarded without the BS.
