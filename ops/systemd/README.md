# Persistent review-host hygiene

`ReviewBackend` sweeps stale `review-*` directories before every review, but a host can sit idle after SIGKILL/OOM. The instance timer is the independent cleanup layer for the two commissioned RYT review lanes.

Instance `%i` maps directly to the deployed lane number:

- `01` → user `ryt-pr-review-01`, runner `ryt-birdinference-review-01`
- `02` → user `ryt-pr-review-02`, runner `ryt-birdinference-review-02`

The session root remains inside each runner's stable `_work/_temp`, so the in-process startup sweep and the systemd janitor act on the same directory without changing the runner service environment.

The janitor refuses symlink, foreign-owned, non-directory, or group/world-accessible `review-*` entries. It only removes entries older than the source-controlled stale threshold, which is always greater than the maximum review wall time in `ryt/locks.json`.

After the updated runtime has been deployed to `/opt/ryt-pr-agent/runtime`:

```bash
for lane in 01 02; do
  user="ryt-pr-review-$lane"
  root="/opt/ryt-runners/ryt-birdinference-review-$lane/_work/_temp/ryt-mirrobot-sessions"
  sudo install -d -m 0700 -o "$user" -g "$user" "$root"
done
sudo install -m 0644 ops/systemd/ryt-mirrobot-hygiene@.service /etc/systemd/system/
sudo install -m 0644 ops/systemd/ryt-mirrobot-hygiene@.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ryt-mirrobot-hygiene@01.timer ryt-mirrobot-hygiene@02.timer
```

Before enabling, run each lane once in dry-run mode as its service user. Do **not** point this service at a parent runner directory and do not run it as root.
