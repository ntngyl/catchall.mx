# CLAUDE.md - AI-Assisted Deployment Guide

This file helps AI assistants (Claude, GPT, etc.) deploy CatchAll.mx on a fresh VPS.

## Project Overview

CatchAll.mx is a DNS-based email forwarding service. Users configure DNS records, and we forward all emails from `*@theirdomain.com` to their specified email address.

## Architecture

```
Postfix (SMTP) → Policy Daemon → Forward Email → Delete
                      ↓
                 DNS Lookup (TXT record)
                      ↓
                 Redis (rate limits, verification status)
```

## Quick Deploy Commands

### For AI Assistants: Copy-Paste Ready

```bash
# 1. SYSTEM SETUP
apt update && apt upgrade -y
apt install -y postfix redis-server python3-pip python3-venv nginx certbot python3-certbot-nginx ufw fail2ban

# 2. CREATE DIRECTORIES
mkdir -p /opt/catchall
mkdir -p /var/spool/catchall/queue
mkdir -p /var/log/catchall
chown -R nobody:nogroup /var/spool/catchall
chown -R nobody:nogroup /var/log/catchall

# 3. INSTALL PYTHON DEPENDENCIES
pip3 install flask redis dnspython

# 4. FIREWALL
ufw allow 22/tcp
ufw allow 25/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
```

## File Locations

| File | Location | Purpose |
|------|----------|---------|
| forward_email.py | /opt/catchall/ | Main email processor |
| policy_daemon.py | /opt/catchall/ | Postfix policy service |
| verification.py | /opt/catchall/ | Sends verification emails |
| queue_manager.py | /opt/catchall/ | Manages email queue |
| web_api.py | /opt/catchall/ | Web API & DNS checker |
| forwarder.py | /opt/catchall/ | SMTP forwarding module |

## Configuration Files to Create

### 1. Environment File: `/etc/catchall.env`

```bash
# SMTP Configuration (for sending verification emails)
SMTP_HOST=smtp.your-provider.com
SMTP_PORT=587
SMTP_USERNAME=your-email@domain.com
SMTP_PASSWORD=your-smtp-password
FROM_EMAIL=verify@yourdomain.com
FROM_NAME=CatchAll

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Your domain
DOMAIN=catchall.mx
```

### 2. Postfix Main Config: Append to `/etc/postfix/main.cf`

```
# CatchAll.mx Configuration
smtpd_recipient_restrictions =
    permit_mynetworks,
    reject_unauth_destination,
    check_policy_service inet:127.0.0.1:10032

# Virtual transport for catchall domains
virtual_transport = catchall:
catchall_destination_recipient_limit = 1
```

### 3. Postfix Master Config: Append to `/etc/postfix/master.cf`

```
# CatchAll pipe transport
catchall   unix  -       n       n       -       -       pipe
  flags=DRhu user=nobody argv=/usr/bin/python3 /opt/catchall/forward_email.py ${recipient}
```

### 4. Systemd Service: `/etc/systemd/system/catchall-policy.service`

```ini
[Unit]
Description=CatchAll.mx Policy Daemon
After=network.target redis.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/catchall
ExecStart=/usr/bin/python3 /opt/catchall/policy_daemon.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 5. Systemd Service: `/etc/systemd/system/catchall-web.service`

```ini
[Unit]
Description=CatchAll.mx Web API
After=network.target redis.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/catchall
EnvironmentFile=/etc/catchall.env
ExecStart=/usr/bin/python3 /opt/catchall/web_api.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 6. Nginx Config: `/etc/nginx/sites-available/catchall`

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        root /var/www/catchall;
        index index.html;
        try_files $uri $uri/ =404;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:5000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /verify/ {
        proxy_pass http://127.0.0.1:5000/verify/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## DNS Records Required

For the **server domain** (e.g., catchall.mx):

```
Type  Host    Value                   TTL
A     @       YOUR_SERVER_IP          3600
A     mail    YOUR_SERVER_IP          3600
MX    @       mail.catchall.mx        3600
TXT   @       v=spf1 ip4:YOUR_IP -all 3600
```

## Step-by-Step Deployment

### Phase 1: Server Setup

```bash
# Update system
apt update && apt upgrade -y

# Install packages
apt install -y postfix redis-server python3-pip nginx certbot python3-certbot-nginx

# During Postfix setup, select "Internet Site" and enter your domain

# Install Python packages
pip3 install flask redis dnspython
```

### Phase 2: Copy Source Files

Copy all `.py` files from `src/` to `/opt/catchall/`:
- forward_email.py
- policy_daemon.py
- verification.py
- queue_manager.py
- web_api.py
- forwarder.py

Make them executable:
```bash
chmod +x /opt/catchall/*.py
```

### Phase 3: Configure Postfix

Edit `/etc/postfix/main.cf` and add:
```
smtpd_recipient_restrictions =
    permit_mynetworks,
    reject_unauth_destination,
    check_policy_service inet:127.0.0.1:10032

virtual_transport = catchall:
catchall_destination_recipient_limit = 1
```

Edit `/etc/postfix/master.cf` and add:
```
catchall   unix  -       n       n       -       -       pipe
  flags=DRhu user=nobody argv=/usr/bin/python3 /opt/catchall/forward_email.py ${recipient}
```

### Phase 4: Configure Services

```bash
# Create environment file
cat > /etc/catchall.env << 'EOF'
SMTP_HOST=smtp.your-provider.com
SMTP_PORT=587
SMTP_USERNAME=your@email.com
SMTP_PASSWORD=your-password
FROM_EMAIL=verify@yourdomain.com
FROM_NAME=CatchAll
EOF

# Create systemd services (see above)
# Enable and start services
systemctl daemon-reload
systemctl enable catchall-policy catchall-web
systemctl start catchall-policy catchall-web
systemctl restart postfix
```

### Phase 5: Configure Nginx & SSL

```bash
# Copy web files
mkdir -p /var/www/catchall
cp index.html /var/www/catchall/

# Configure Nginx
# Create config file as shown above
ln -s /etc/nginx/sites-available/catchall /etc/nginx/sites-enabled/
nginx -t && systemctl restart nginx

# Get SSL certificate
certbot --nginx -d yourdomain.com
```

### Phase 6: DNS Setup

Add these DNS records for your server domain:
- A record: `@` → `YOUR_SERVER_IP`
- A record: `mail` → `YOUR_SERVER_IP`
- MX record: `@` → `mail.yourdomain.com` (priority 10)
- TXT record: `v=spf1 ip4:YOUR_SERVER_IP -all`

## Verification Checklist

```bash
# Check services are running
systemctl status catchall-policy
systemctl status catchall-web
systemctl status postfix
systemctl status redis
systemctl status nginx

# Check logs
tail -f /var/log/catchall/policy.log
tail -f /var/log/catchall/forwarder.log

# Test DNS checker API
curl "http://localhost:5000/api/check-dns?domain=example.com"

# Test email flow (from another server)
echo "Test" | mail -s "Test" test@configured-domain.com
```

## Common Issues

### 1. Emails not being received
- Check Postfix logs: `tail -f /var/log/mail.log`
- Check policy daemon: `systemctl status catchall-policy`
- Verify DNS records are correct

### 2. Verification emails not sent
- Check SMTP credentials in `/etc/catchall.env`
- Check verification log: `tail -f /var/log/catchall/verification.log`

### 3. Rate limiting too strict
- User can set `catchall-limit=100` in DNS TXT record

### 4. Redis connection issues
- Check Redis is running: `systemctl status redis`
- Test connection: `redis-cli ping`

## Security Hardening

```bash
# Enable firewall
ufw allow 22/tcp
ufw allow 25/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable

# Install fail2ban
apt install fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# Secure Redis (bind to localhost only - default)
# Check /etc/redis/redis.conf has: bind 127.0.0.1
```

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| SMTP_HOST | Yes | - | SMTP server for verification emails |
| SMTP_PORT | Yes | 587 | SMTP port |
| SMTP_USERNAME | Yes | - | SMTP username |
| SMTP_PASSWORD | Yes | - | SMTP password |
| FROM_EMAIL | Yes | - | From address for verification emails |
| FROM_NAME | No | CatchAll | Display name for verification emails |
| REDIS_HOST | No | localhost | Redis server host |
| REDIS_PORT | No | 6379 | Redis server port |
| DOMAIN | Yes | - | Your server's domain |

## For Vibecoders

If you're using an AI assistant to deploy this:

1. **Give the AI this file** - It contains everything needed
2. **Provide your details:**
   - Server IP address
   - Domain name
   - SMTP credentials (use a service like Mailgun, SendGrid, or Postmark)
3. **Let the AI run the commands** - It will set everything up
4. **Test with a real email** - Send to `test@yourdomain.com`

The AI should be able to:
- Copy all source files to `/opt/catchall/`
- Configure Postfix, Redis, Nginx
- Set up systemd services
- Configure SSL with Certbot
- Set up firewall rules

## Troubleshooting Commands

```bash
# View all logs at once
tail -f /var/log/catchall/*.log

# Check what's in Redis
redis-cli KEYS '*'

# Check queue
ls -la /var/spool/catchall/queue/

# Test policy daemon directly
echo -e "request=smtpd_access_policy\nrecipient=test@domain.com\n\n" | nc localhost 10032

# Restart everything
systemctl restart postfix catchall-policy catchall-web nginx
```
