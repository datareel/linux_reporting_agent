# Utilities

Standalone programs that make a report about the host, for example a
login summary. Each one works on its own, with no agent installed, and
can hand its result to the DataReel Reporting Agent for Linux, which
sends it to the report server and the DataReel System Monitor (DRSM)
dashboard. They use the agent's hook uploads (`drra submit`,
`/etc/drra/uploads.d`), see "Hook uploads" in the top README.

| Util | What it reports |
|------|-----------------|
| [auth_watch](auth_watch/README.md) | Failed and accepted logins since the last run, remote apart from the host's own |

## Layout

Each util lives in `utils/<name>/`:

| File | What it is |
|------|------------|
| `<name>` | The program (a script, or built by its own Makefile) |
| `README.md` | What it reports, its options, how to install it |
| `<name>.ini` | Upload hook file for the agent: `/etc/drra/uploads.d/<name>.ini` |
| `<name>.cron` | Schedule example for `/etc/cron.d/<name>` (when it runs on a schedule) |
| `drsm/uploads/<name>/` | DRSM manifest (`plugin.conf`, `probe.sh`): copy to `<drsm>/plugins/uploads/<name>` on the monitor host |
| `tests/` | Test script and fixtures, no root or network needed |

The upload hook ID, the DRSM manifest folder and the util are all
named `<name>` (a-z, 0-9 and `_`, up to 32 characters).

## Command line

Every util takes these options, and its own:

| Option | Meaning |
|--------|---------|
| (none) | Print the report to stdout |
| `--out FILE` | Write the report to FILE |
| `--format F` | Output format, when the util has more than one (CSV is the usual default) |
| `--submit` | Hand the report to the agent: `drra submit --hook <name> <file>` |
| `--now` | With `--submit`: the agent sends it within seconds instead of with the next report |
| `--hook ID` | Upload hook ID, default `<name>` |
| `--drra PATH` | Agent program, default `drra` in PATH or `/usr/sbin/drra` |
| `--drra-config INI` | Agent settings file (`drra -c INI`), for tests |
| `-h`, `--help`, `--version` | |

Exit status 0 when the report was made (and submitted), 1 on an error,
2 on a bad option. A util that remembers where it stopped (a log
position) saves it only after the report was written or submitted, so
a failed submit is read again next time.

With `--submit` the util always sends the format its DRSM manifest
reads, whatever `--format` says. `drra submit` needs root or the
`drra-upload` group.

## Sending a report to the dashboard

1. On the monitor host, copy the manifest to DRSM:
   `cp -r utils/<name>/drsm/uploads/<name> <drsm>/plugins/uploads/`.
   The report server's `hook.php` reads it from `[hooks] manifest_dir`
   (the same folder on a DRSM install), and the host needs `UPLOADS_DIR`
   and `UPLOADS=auto` (or a list) in its DRSM host file.
2. On the agent host, install the util and its upload hook:
   `sudo utils/install_util.sh <name>` shows what it would do (dry run),
   `--apply` does it. It puts the program in
   `/usr/local/libexec/drra-utils/` and the hook file in
   `/etc/drra/uploads.d/`, and with `--cron` the schedule in
   `/etc/cron.d/`.
3. Run it once by hand: `/usr/local/libexec/drra-utils/<name> --submit --now`,
   then `drra uploads` shows the hook's state.

## Report hooks instead of uploads

A util whose result belongs in every report, as one check, can be a
report hook instead: the agent runs every program in
`/etc/drra/report.d` with each report and puts its DRSM lines in the
`HOOKS` section (see "Report hooks" in the top README). Such a util
prints DRSM plugin lines (`INFO - `, `WARNING - `, `ERROR - `,
`METRIC`) with `--report-hook` and exits 0 OK, 1 WARNING, 2 ERROR or
3 UNKNOWN. Use an upload for a table, for data made now and then, or
for a program that takes longer than the hook timeout (60 seconds).

## Adding a util

Copy `auth_watch/` as a start: the program with the options above,
its `README.md`, the `.ini`, the DRSM manifest (`FORMAT` is one of
`drsm-lines`, `kv-sections`, `json`, `csv`, `xccdf-results`, `text`,
`html`; the rules can only use values the format gives, so `csv` gives
only `rows`) and a test that runs without root. Add it to the table at
the top.
