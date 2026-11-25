# CatchAll.mx

Free catch-all email forwarding for your own domain, configured entirely in DNS.

Add two DNS records and every address at your domain is forwarded to the inbox you already use. There is no account, no dashboard and no paid plan, and mail is not kept after it is delivered.

This repository is the code that runs [catchall.mx](https://catchall.mx).

## Using the service

1. Add an MX record on your domain: `mail.catchall.mx`, priority 10.
2. Add a TXT record on your domain: `catchall-forward=you@example.com`.
3. Check the domain at [catchall.mx](https://catchall.mx) and press the button to send a confirmation email to that inbox. Click the link in it and forwarding starts.

The confirmation exists so nobody can point a domain at someone else's address. Every destination address confirms once per domain.

Step-by-step instructions for common DNS providers are at [catchall.mx/guides](https://catchall.mx/guides/), and the [record builder](https://catchall.mx/setup/) reads a domain's current DNS and lists exactly what to add, change or delete.

### Optional records

All settings are TXT records on the domain itself.

| Record | What it does |
|---|---|
| `catchall-forward=you@example.com` | Default destination for every address |
| `catchall-route=sales:team@example.com` | Send one address (or a `*` pattern) somewhere else |
| `catchall-block=old,promo-*` | Refuse mail to these addresses |
| `catchall-only=hello,billing` | Accept only these addresses and refuse the rest |
| `catchall-limit=100` | Maximum emails per day |
| `catchall-size=5` | Lower the maximum message size, in MB (default and maximum 20) |
| `catchall-spam=strict` | Spam filtering: `strict`, `moderate` or `off` |

Per-domain DKIM is optional: publish the key shown at [catchall.mx/dkim/setup](https://catchall.mx/dkim/setup) under the selector `catchall`, and forwarded mail that needs re-signing is signed by your own domain.

## What is stored

- **Mail content:** only while it waits. Mail for a destination that has not confirmed yet is held for up to 24 hours, then deleted. Mail flagged as a likely forgery is held in quarantine for up to 7 days. Everything else is forwarded and not kept.
- **Per domain:** whether it is confirmed, which destinations consented, a daily counter, and a DKIM key if one was generated.
- **Logs:** mail and application logs are rotated daily and kept at most 7 days.
- **Website:** no analytics and no cookies. DNS lookups made with the tools are not saved.

## How it works

```
sender ─▶ postscreen (DNS blocklists, protocol checks)
       ─▶ Postfix smtpd ─▶ policy_daemon.py   (is the domain set up? is the address blocked? rate limit)
                        ─▶ rspamd milter      (scoring; DKIM/ARC signing for mail we originate)
       ─▶ forward_email.py (pipe, one recipient at a time)
            ├─ routing.py       read the domain's TXT records, pick the destination
            ├─ consent check    confirmed? forward : queue + confirmation email
            ├─ from_rewrite.py  keep the message untouched when its own DKIM signature
            │                   aligns with From; otherwise rewrite From and sign
            └─ forwarder.py     deliver through 127.0.0.1:10025
```

| File | Purpose |
|---|---|
| `forward_email.py` | Entry point Postfix pipes each message to |
| `routing.py` | Parses the `catchall-*` TXT records; per-destination consent |
| `policy_daemon.py` | Postfix policy service on port 10032 |
| `verification.py` | Confirmation emails and links |
| `queue_manager.py` | Holds mail for unconfirmed destinations, 24 hour limit |
| `from_rewrite.py` | DMARC-safe From rewriting and DKIM signing |
| `dkim_manager.py` | Per-domain DKIM keys |
| `forwarder.py` | SMTP delivery of forwarded mail |
| `abuse.py`, `spam_detector.py`, `quarantine_manager.py`, `bounce_monitor.py` | Abuse blocking, filtering, quarantine, bounce tracking |
| `dns_check.py` | The setup checker behind `/api/check-dns` |
| `dns_tools.py` | MX, SPF, DKIM and DMARC lookups behind `/api/tools/…` |
| `web_api.py` | Flask app: checker, confirmation, DKIM, abuse report |
| `web/` | The website. `web/build.py` generates the guide and tool pages |
| `config/` | The Postfix, nginx, systemd, cron and logrotate settings in use |

## API

```bash
curl "https://catchall.mx/api/check-dns?domain=example.com"     # forwarding setup check
curl "https://catchall.mx/api/tools/all?domain=example.com"     # MX, SPF, DKIM, DMARC
curl "https://catchall.mx/api/tools/dkim?domain=example.com&selector=google"
```

The tools endpoints are limited to 120 lookups an hour per visitor.

## Running your own

The code assumes a single Ubuntu server with Postfix, rspamd, Redis, nginx and a local resolver (unbound), installed in `/opt/catchall`. `config/` holds the settings the live server uses, with the host name as the only thing to change. There is no installer; expect to read the config files and adapt them. The server needs a clean IP address with matching forward and reverse DNS, and port 25 open in both directions.

```bash
pip3 install -r requirements.txt
python3 web/build.py        # generate the static guide and tool pages
```

## Contributing

Issues and pull requests are welcome at [github.com/ntngyl/catchall.mx](https://github.com/ntngyl/catchall.mx/issues). To report abuse of the service, use [catchall.mx/report](https://catchall.mx/report).

## License

MIT, see [LICENSE](LICENSE).
