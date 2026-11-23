#!/bin/bash
# Email forwarder - receives recipient as argument, email content from stdin

RECIPIENT="$1"
DOMAIN=$(echo "$RECIPIENT" | cut -d'@' -f2)

# Log
echo "$(date) - Processing email for $RECIPIENT (domain: $DOMAIN)" >> /var/log/catchall/forwarder.log

# Get forward address from DNS
FORWARD_TO=$(dig +short $DOMAIN TXT | grep catchall-forward | sed 's/.*catchall-forward=\([^"]*\).*/\1/' | head -1)

if [ -z "$FORWARD_TO" ]; then
    echo "$(date) - No forward address found for $DOMAIN" >> /var/log/catchall/forwarder.log
    exit 0
fi

echo "$(date) - Forwarding to: $FORWARD_TO" >> /var/log/catchall/forwarder.log

# Reinject via port 10025 which bypasses the pipe and uses normal SMTP routing
# Use netcat to inject directly to port 10025
(
    echo "HELO catchall.mx"
    echo "MAIL FROM:<bounce@catchall.mx>"
    echo "RCPT TO:<$FORWARD_TO>"
    echo "DATA"
    cat -
    echo "."
    echo "QUIT"
) | nc -q 1 127.0.0.1 10025 >> /var/log/catchall/forwarder.log 2>&1

echo "$(date) - Forwarded successfully to $FORWARD_TO" >> /var/log/catchall/forwarder.log
exit 0
