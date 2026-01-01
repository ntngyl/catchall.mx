# Self-Hosting Guide

Complete guide to hosting your own CatchAll.mx instance.

## Prerequisites

- **VPS/Server**: Ubuntu 22.04+ recommended (1GB RAM minimum)
- **Domain**: A domain you control (e.g., `catchall.yourdomain.com`)
- **SMTP Service**: For sending verification emails (Mailgun, SendGrid, Postmark, etc.)

## Step 1: Server Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y \
    postfix \
    redis-server \
    python3 \
    python3-pip \
    python3-venv \
    nginx \
    certbot \
    python3-certbot-nginx \
    ufw \
    fail2ban

# During Postfix installation:
# - Select "Internet Site"
# - Enter your domain name
```

## Step 2: Create Directories

```bash
# Application directory
sudo mkdir -p /opt/catchall

# Queue directory
sudo mkdir -p /var/spool/catchall/queue
sudo chown -R nobody:nogroup /var/spool/catchall

# Log directory
sudo mkdir -p /var/log/catchall
sudo chown -R nobody:nogroup /var/log/catchall

# Web directory
sudo mkdir -p /var/www/catchall
```

## Step 3: Clone & Install

```bash
# Clone the repository
git clone https://github.com/ntngyl/catchall.mx.git
cd catchall.mx

# Install Python dependencies
pip3 install -r requirements.txt

# Copy source files
sudo cp src/*.py /opt/catchall/
sudo chmod +x /opt/catchall/*.py

# Copy web files
sudo cp web/index.html /var/www/catchall/
```

## Step 4: Configure Environment

```bash
# Copy example environment file
sudo cp config/catchall.env.example /etc/catchall.env

# Edit with your values
sudo nano /etc/catchall.env
```

Fill in your values:
```bash
SMTP_HOST=smtp.mailgun.org
SMTP_PORT=587
SMTP_USERNAME=postmaster@mg.yourdomain.com
SMTP_PASSWORD=your-mailgun-password
FROM_EMAIL=verify@yourdomain.com
FROM_NAME=YourDomain
REDIS_HOST=localhost
REDIS_PORT=6379
DOMAIN=yourdomain.com
```

## Step 5: Configure Postfix

```bash
# Append to main.cf
sudo cat config/postfix/main.cf.append >> /etc/postfix/main.cf

# Append to master.cf
sudo cat config/postfix/master.cf.append >> /etc/postfix/master.cf

# Restart Postfix
sudo systemctl restart postfix
```

## Step 6: Configure Systemd Services

```bash
# Copy service files
sudo cp config/systemd/*.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable and start services
sudo systemctl enable catchall-policy catchall-web
sudo systemctl start catchall-policy catchall-web

# Check status
sudo systemctl status catchall-policy
sudo systemctl status catchall-web
```

## Step 7: Configure Nginx

```bash
# Copy nginx config
sudo cp config/nginx/catchall.conf /etc/nginx/sites-available/

# Edit domain name
sudo nano /etc/nginx/sites-available/catchall.conf
# Replace "yourdomain.com" with your actual domain

# Enable site
sudo ln -s /etc/nginx/sites-available/catchall.conf /etc/nginx/sites-enabled/

# Remove default site (optional)
sudo rm /etc/nginx/sites-enabled/default

# Test and reload
sudo nginx -t && sudo systemctl reload nginx
```

## Step 8: Get SSL Certificate

```bash
# Get certificate from Let's Encrypt
sudo certbot --nginx -d yourdomain.com -d mail.yourdomain.com

# Certbot will automatically update nginx config
```

## Step 9: Configure DNS

Add these DNS records for your domain:

| Type | Host | Value | TTL |
|------|------|-------|-----|
| A | @ | YOUR_SERVER_IP | 3600 |
| A | mail | YOUR_SERVER_IP | 3600 |
| MX | @ | mail.yourdomain.com | 3600 |
| TXT | @ | v=spf1 ip4:YOUR_SERVER_IP -all | 3600 |

Optional but recommended:
| Type | Host | Value | TTL |
|------|------|-------|-----|
| TXT | _dmarc | v=DMARC1; p=quarantine; rua=mailto:you@email.com | 3600 |

## Step 10: Configure Firewall

```bash
# Enable UFW
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 25/tcp    # SMTP
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable
```

## Step 11: Set Up Fail2ban

```bash
# Fail2ban should be running by default
sudo systemctl status fail2ban

# Check jails
sudo fail2ban-client status
```

## Step 12: Set Up Cron Job for Queue Cleanup

```bash
# Edit crontab
sudo crontab -e

# Add this line to clean up expired emails daily
0 3 * * * /usr/bin/python3 /opt/catchall/queue_manager.py
```

## Verification

### Check all services are running:

```bash
sudo systemctl status postfix
sudo systemctl status redis
sudo systemctl status nginx
sudo systemctl status catchall-policy
sudo systemctl status catchall-web
```

### Test DNS checker API:

```bash
curl "https://yourdomain.com/api/check-dns?domain=example.com"
```

### Test email flow:

1. Configure a test domain's DNS:
   - MX: `mail.yourdomain.com` (priority 10)
   - TXT: `catchall-forward=your@email.com`

2. Wait for DNS propagation (5-30 minutes)

3. Send a test email to `test@testdomain.com`

4. Check logs:
```bash
tail -f /var/log/catchall/policy.log
tail -f /var/log/catchall/forwarder.log
tail -f /var/log/mail.log
```

## Troubleshooting

### Emails not being received

```bash
# Check Postfix
sudo tail -f /var/log/mail.log

# Check policy daemon
sudo journalctl -u catchall-policy -f

# Test policy daemon directly
echo -e "request=smtpd_access_policy\nrecipient=test@domain.com\n\n" | nc localhost 10032
```

### Verification emails not sending

```bash
# Check verification log
sudo tail -f /var/log/catchall/verification.log

# Test SMTP credentials manually
python3 -c "
import smtplib
server = smtplib.SMTP('your-smtp-host', 587)
server.starttls()
server.login('your-username', 'your-password')
print('SMTP works!')
server.quit()
"
```

### Web interface not loading

```bash
# Check nginx
sudo nginx -t
sudo tail -f /var/log/nginx/error.log

# Check web API
sudo journalctl -u catchall-web -f
```

### Redis connection issues

```bash
# Check Redis
sudo systemctl status redis
redis-cli ping
```

## Updating

```bash
cd /path/to/catchall.mx
git pull

# Update source files
sudo cp src/*.py /opt/catchall/

# Restart services
sudo systemctl restart catchall-policy catchall-web
```

## Security Recommendations

1. **Enable automatic updates**: `sudo apt install unattended-upgrades`
2. **Use strong SSH keys**: Disable password authentication
3. **Monitor logs**: Set up log rotation and monitoring
4. **Regular backups**: Back up `/etc/catchall.env` and Redis data
5. **Rate limiting**: Nginx rate limiting for API endpoints

## Support

- GitHub Issues: https://github.com/ntngyl/catchall.mx/issues
- Email: nitin@mrig.in
