# Multi-Vendors Cloud Configuration via NETCONF (CallMe Manage)

Manage Cisco / Juniper / Huawei network devices through NETCONF call-home.

## Install (Ubuntu 24.04)

```bash
git clone https://github.com/Thada-Saket/Multi-Vendors-Cloud-Configuration-via-Netconf.git
cd Multi-Vendors-Cloud-Configuration-via-Netconf
sudo ./install.sh
```

The installer sets up everything (anything already present is skipped, so it is safe to run
again) and only asks:

1. A password for the system's own PostgreSQL user, and whether Redis keeps no password (the
   default) or gets one you choose; a Redis that already has a password is only asked for it.
   Nothing is generated or changed behind your back, and any character is allowed.
2. Which IP devices call home to (pick an interface or type an IP)
3. Which address of this server listens for call-home: all interfaces (default) or one
   interface's IP (`CALLHOME_LISTEN_ADDRESS`)
4. The website address (`SITE_URL`) and path (`ROOT_PATH`: `/`, or e.g. `/cmm/` behind a
   reverse proxy) - press Enter to skip
5. Where devices download their config (`BOOTSTRAP_BASE_URL`) - press Enter to leave it empty
   (recommended: straight from this machine)
6. Whether to set up Cloudflare / Email / Google now (optional - the system works without them)
7. The first website account: username, email, password

When it finishes, the system runs as Linux services: it starts on boot and restarts after a
crash. Website at `https://<machine>:8080` · API and bootstrap files at `:8000` · device
call-home at `:4334`

**Updating:** `git pull`, then `sudo ./install.sh` again (no questions are asked
twice; your settings are kept)

## After installing

All settings are in one file: `/etc/callmemanage/callmemanage.conf` (outside the code folder,
so `git pull` never touches it). The file explains every setting and where to get each key.

| Command | What it does |
|---|---|
| `callmemanage status` | Is it running, and where is the website |
| `sudo callmemanage config` | Edit the settings → checked → website rebuilt if needed → restarted (a wrong value is not saved; the running system keeps going) |
| `sudo callmemanage setup turnstile` / `email` / `google` | Turn on one service, step by step, with a key check |
| `sudo callmemanage disable turnstile` / `email` / `google` | Turn that service off |
| `sudo callmemanage user add` | Create a website account |
| `sudo callmemanage user passwd <name>` | Set a new password for a user who forgot it |
| `callmemanage logs` | Follow the log |
| `callmemanage help` | Every command |

The services can also be controlled with systemctl. One name controls both the backend and
the website; each can still be checked on its own:

```bash
sudo systemctl start | stop | restart callmemanage
systemctl status callmemanage.slice           # both at once (a stopped one is missing from the list)
systemctl status callmemanage-backend         # or callmemanage-frontend
journalctl -u callmemanage-backend -u callmemanage-frontend -f
```

`systemctl status callmemanage` only says whether the group was started; use the slice or
`callmemanage status` to see if both are really running.

**Uninstall / start over:** `sudo ./uninstall.sh` (same as `sudo ./install.sh --uninstall`
or `sudo callmemanage uninstall`) removes the services, the command and the config file (a root-only backup is kept
in `/root`). It asks before deleting the database, the Redis password, the built files and the
call-home key - all kept by default. PostgreSQL, Redis and Node.js stay installed.

After editing the file by hand, run `sudo callmemanage apply` (not only a restart): it checks
the file first and rebuilds the website when `ROOT_PATH` changed.

## External services (optional)

| Service | When off (`no`) | Turn on with |
|---|---|---|
| Cloudflare Turnstile | No bot check (rate limits only); works without Internet | `sudo callmemanage setup turnstile` |
| Email (Gmail) | A forgotten password is reset by an admin (`sudo callmemanage user passwd`) | `sudo callmemanage setup email` |
| Google sign-in | No Google button | `sudo callmemanage setup google` |

`APP_ENV=production` requires Cloudflare with a real key.

## Behind a reverse proxy (e.g. `https://www.example.ac.th/cmm/`)

- `SITE_URL=https://www.example.ac.th` and `ROOT_PATH=/cmm/`
- The proxy forwards `/cmm/...` to `FRONTEND_PORT` **unchanged - do not strip `/cmm`**. The API
  is at `/cmm/api/...` on the same port. Apache example:
  ```apache
  ProxyPass        /cmm/  https://<this machine>:8080/cmm/
  ProxyPassReverse /cmm/  https://<this machine>:8080/cmm/
  ```
  Keep the trailing slash the same on both sides.
- Leave `BOOTSTRAP_BASE_URL` empty (recommended): devices download their config straight from
  `https://<call-home IP>:8000`, with no DNS needed. Set it to
  `https://www.example.ac.th/cmm/api` only if devices cannot reach this machine directly; the
  proxy then needs an RSA certificate, because many Cisco IOS-XE versions cannot connect to an
  ECDSA-only one.
- The call-home port (`4334`) is SSH and cannot go through an HTTP proxy; devices must reach
  this machine directly.

## For developers

```bash
cp install-packages/callmemanage.conf.example callmemanage.conf   # then fill in DB_URL / REDIS_URL / JWT_SECRET_KEY
export CALLMEMANAGE_CONF=$PWD/callmemanage.conf
./install-packages/start_service.sh   # runs in the terminal (instead of the services) and writes logs/
```
