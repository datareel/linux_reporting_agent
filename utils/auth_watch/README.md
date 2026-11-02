# auth_watch

Failed and accepted logins since the last run, from the systemd journal
or `/var/log/secure`, for RHEL 8, 9 and 10. Remote attempts are kept
apart from the host's own, so the owner's typos do not look like an
attack:

| Scope | Which logins |
|-------|--------------|
| `remote` | sshd (and any PAM service with a remote host, such as cockpit) from another address |
| `trusted` | Same, from an address given with `--trusted` (for example the office network) |
| `localhost` | sshd from `::1` or `127.0.0.1` (tunnels, scripts, `ssh localhost`) |
| `local` | Password prompts on the host: gdm, polkit, sudo, su, console login |

Events: `failed` (a wrong password or key), `invalid_user` (no such
user), `too_many` (sshd closed the connection after too many tries),
`preauth_closed` (closed before logging in, typical of scanners on a
key-only server), `accepted`. sshd lines come from `sshd`,
`sshd-session` (RHEL 10) and `sshd-auth`. One attempt can log more than
one event, for example `invalid_user` and `failed`.

## Output

CSV, one row per scope, service, event, method, user and source, with
the count and the first and last time:

```
scope,service,event,method,user,source,count,first,last
remote,sshd,failed,password,root,203.0.113.7,2,Oct 30 02:12:00,Oct 30 02:12:04
remote,sshd,invalid_user,,admin,203.0.113.7,1,Oct 30 02:11:01,Oct 30 02:11:01
localhost,sshd,accepted,publickey,owner,127.0.0.1,87,Nov  1 10:20:01,Nov  1 22:21:27
local,polkit-1,failed,password,owner,,1,Nov  1 22:33:28,Nov  1 22:33:28
```

`--format lines` (and `--submit`) gives DRSM lines: the same table as
`UPLOAD columns|` and `UPLOAD row|` lines, and `DETAIL` values the
dashboard rules use: `<scope>_<event>` counts (`remote_failed`,
`remote_invalid_user`, `remote_too_many`, `remote_preauth_closed`,
`remote_accepted`, the same for `trusted` and `localhost`,
`local_failed`, `local_accepted`), `<scope>_sources` (addresses with a
failure), `lines_read`, `events`, `first_event`, `last_event`.

## Where it starts

The position is saved in `/var/lib/drra_utils/auth_watch.state` (root)
or `~/.local/state/drra_utils/auth_watch.state`: the journal cursor, or
the secure log's inode and size. The next run starts there; after a
log rotation it reads the rest of the rotated file
(`/var/log/secure-YYYYMMDD`) first. The first journal run reads the
last 24 hours, the first secure run the whole current file.
`--since TIME` starts somewhere else, `--no-save` leaves the position
alone, `--input FILE` parses a saved log without any position.

## Options

```
auth_watch [--source auto|journal|secure] [--log FILE] [--input FILE]
           [--since TIME] [--state FILE] [--no-save] [--sudo]
           [--trusted LIST] [--format csv|lines] [--out FILE]
           [--submit [--now] [--hook ID] [--drra PATH] [--drra-config INI]]
```

`--sudo` reads the logs and runs `drra` with `sudo -n`, for a user with
sudo rights. Without root, the journal shows only the user's own
entries.

## On the dashboard

```
# On the monitor host
cp -r utils/auth_watch/drsm/uploads/auth_watch <drsm>/plugins/uploads/

# On the agent host
sudo utils/install_util.sh auth_watch --cron            # dry run
sudo utils/install_util.sh auth_watch --cron --apply
sudo /usr/local/libexec/drra-utils/auth_watch --submit --now
drra uploads
```

The cron file runs it every 15 minutes, and the agent sends it with its
next report. The manifest (`FORMAT=drsm-lines`, `DISPLAY=table`) warns
when `remote_failed`, `remote_invalid_user` or `remote_too_many` is
above 0, raises an error at 50 remote failures, and warns when the data
is over 2 hours old. Only remote values are in the rules: localhost and
local failures show in the table but do not alert. Change the rules for
one host with `uploads_auth_watch_WARN_IF=...` in its DRSM host file.

## Test

```
utils/auth_watch/tests/auth_watch_test.sh
DRSM_DIR=~/git/dr_system_monitor utils/auth_watch/tests/auth_watch_test.sh
```

The fixtures are RHEL 8 `/var/log/secure` and RHEL 10 journal lines,
with documentation addresses (203.0.113.0/24, 198.51.100.0/24,
192.0.2.0/24, 2001:db8::/32). With the agent built (`make`), php and
curl the test also sends a report through `drra submit` to `hook.php`
on a local `php -S` server; with `DRSM_DIR` it runs the DRSM probe on it.
