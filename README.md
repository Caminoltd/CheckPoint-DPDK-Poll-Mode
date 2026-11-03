# CheckPoint-DPDK-Poll-Mode

`Set-PollSleep.ps1` — enable, disable and check **UPPAK adaptive poll sleep** on
Check Point Gaia gateways, from a Windows jump host, with a safe sequential
reboot of cluster members.

Built for virtual and cloud training labs, where UPPAK's DPDK poll mode leaves
two CPU cores per gateway pinned at 100% around the clock, whether or not any
traffic is flowing.

---

## The problem

From R82.10, SecureXL runs in **UPPAK** (user-space) mode on all gateways.
UPPAK uses DPDK poll mode, so every SND core spins at 100% regardless of load.
On an appliance that is by design. On a virtual lab it means:

> **Two cores per gateway, pinned at 100%, permanently — on a completely idle lab.**

A three-gateway lab burns six cores per student instance, multiplied by the
class size. On a cloud lab platform, somebody is paying for those cycles.

`sk180299` documents the effect and advises trusting `cpview` over Linux tools.

### Measured, on an idle R82.10 lab

| Gateway | Poll sleep OFF | Poll sleep ON |
|---|---|---|
| A-GW-01 | 2 of 8 cores pinned — top two **100% / 100%** | 0 of 8 — top two 13% / 10% |
| A-GW-02 | 2 of 8 cores pinned — top two **100% / 100%** | 0 of 8 — top two 17% / 14% |
| B-GW | 2 of 8 cores pinned — top two **100% / 100%** | 0 of 8 — top two 9% / 7% |

---

## A measurement trap

**`cpstat` and `cpview` cannot see this.** They deliberately report the SND's
*real work* rather than the poll spin — the inverse of the `sk180299` warning.

On the same gateway at the same moment, with poll sleep off:

```
htop                 cores 1 and 2 at 100.0%, both usim_x86 SND threads at ~100%
cpstat os -f cpu     9% usage, 5% user
```

If you measure this with `cpstat` you will conclude there is nothing wrong.
Use `top`/`htop` per-core, or `/proc/stat` — which is what this script does.

---

## What the script does

It picks the right mechanism per gateway automatically:

| Release | Mechanism | Reboot? |
|---|---|---|
| **R82.20+** | config_point parameter `securexl.usim.adaptive_sleep.usim_with_sleep_enabled` | No — applies live |
| **R82.10 and earlier** | the `--enable-poll-sleep=1` launch flag, set by changing the CPU test in `/etc/ppk.boot/etc/dpdk_boot.sh` | Yes — read only at `usim` startup |

When a reboot is needed, members are done **strictly one at a time**: reboot,
wait for SSH to drop, wait for the gateway to return, wait for a healthy
cluster state, verify the flag is live in the running process — and only then
move to the next gateway. Any failure stops with the remaining gateways
untouched.

### Other things it handles so you don't have to

- **Transport** — tries `ssh.exe` with a key, falls back to PuTTY `plink` with a
  password, asked for once.
- **The Windows OpenSSH MAC bug** — the Windows client prefers a broken
  `umac-128-etm@openssh.com` implementation and fails against Gaia with
  *"Corrupted MAC on input"*. The script forces `hmac-sha2` MACs.
- **clish** — if the login shell is clish it switches it to bash and saves the
  configuration through `clish -c "save config"`, which has to be run *after*
  the shell has already changed.
- **Uncached host keys** — accepted automatically, since a freshly launched lab
  has never been connected to.
- **Unreachable gateways** — warned about and skipped, not fatal.

---

## Requirements

- Windows 10/11 jump host with **PowerShell 7** (`pwsh`)
- Either an SSH key for the gateway admin user, **or** PuTTY installed
- Network access to the gateways on TCP 22

No setup on the gateways is required. It is designed to work against a freshly
launched lab instance.

---

## Usage

```powershell
# See the current state. Changes nothing.
pwsh -ExecutionPolicy Bypass -File .\Set-PollSleep.ps1 -Action Check

# Enable poll sleep (reboots R82.10 gateways, one at a time)
pwsh -ExecutionPolicy Bypass -File .\Set-PollSleep.ps1 -Action Enable

# Put it back to the shipped default
pwsh -ExecutionPolicy Bypass -File .\Set-PollSleep.ps1 -Action Disable

# Put the admin login shell back to clish (/etc/cli.sh)
pwsh -ExecutionPolicy Bypass -File .\Set-PollSleep.ps1 -Action RestoreShell
```

### Example output

```
  Current state
  10.1.1.2       R82.10    ACTIVE   pinned:2/8 top:100/100%  set:false   poll sleep not active
  10.1.1.3       R82.10    STANDBY  pinned:2/8 top:100/100%  set:false   poll sleep not active
  198.51.100.1   R82.10    single   pinned:2/8 top:100/100%  set:false   poll sleep not active
  Reboot order: 10.1.1.2 -> 10.1.1.3 -> 198.51.100.1

  ...

  Cores at 90%+ before and after (from /proc/stat)
  Gateway        Before (pinned, top 2)     After (pinned, top 2)
  10.1.1.2       2 of 8  [100/100%]         0 of 8  [10/8%]
  10.1.1.3       2 of 8  [100/100%]         0 of 8  [17/13%]
  198.51.100.1   2 of 8  [100/100%]         0 of 8  [86/35%]
```

`pinned` is the number of cores at 90%+ busy, and `top` the two busiest. The
count is the headline; the percentages are there so the figure can be sanity
checked rather than taken on trust.

---

## Parameters

| Parameter | Default | Notes |
|---|---|---|
| `-Action` | `Check` | `Check`, `Enable`, `Disable`, `RestoreShell` |
| `-Gateways` | `10.1.1.2,10.1.1.3,198.51.100.1` | Rebooted in the order given |
| `-User` | `admin` | Gateway login |
| `-UsePlink` | off | Force PuTTY instead of letting it fall back on its own |
| `-Password` | — | Skips the prompt. Convenient for lab automation, visible in shell history |
| `-NoReboot` | off | Stage the change without rebooting |
| `-NoShellFix` | off | Stop rather than changing a clish login shell to bash |
| `-SettleSec` | `180` | Wait after the last reboot before the final reading. `300` is safer if a gateway is still loading policy |
| `-RebootTimeoutSec` | `600` | Per-gateway wait for a reboot |

### Reboot order matters

Gateways are rebooted in the order given by `-Gateways`. In a cluster the
member rebooted **last** ends up standby, so putting A-GW-01 first leaves
**A-GW-01 active** when the run finishes.

---

## Reverting

```powershell
pwsh -ExecutionPolicy Bypass -File .\Set-PollSleep.ps1 -Action Disable
pwsh -ExecutionPolicy Bypass -File .\Set-PollSleep.ps1 -Action RestoreShell
```

`Disable` restores the shipped `-eq 2` CPU test. `RestoreShell` sets the admin
login shell back to `/etc/cli.sh`. The script also keeps a backup of the
original boot script at `/etc/ppk.boot/etc/dpdk_boot.sh.labbk`.

---

## Caveats

> **Lab use only.**

- **Not supported above two cores.** Max Power states that poll sleep on
  gateways with more than two cores is unsupported and may cause stability
  issues. On current releases a `usim_x86` crash panics and reboots the whole
  gateway. Whether R82.10/R82.20 change this is an open question.
- **There is a performance cost.** Tim Hall measured roughly a 20% single-stream
  fastpath penalty on R82.10, varying by path — around 40% on the slowpath.
  Separate R82.20 testing showed roughly 0.5 ms added to each new connection.
  Neither is noticeable in a training lab.
- **The R82.10 change is a file edit** and will not survive a gateway rebuild,
  and may not survive a Jumbo HFA. It fails silently — the lab simply goes back
  to burning two cores per gateway with nothing to indicate it. Re-run
  `-Action Check` after any rebuild or upgrade.
- **It changes the admin login shell to bash** and saves the configuration,
  because the R82.10 method needs file access. Use `-NoShellFix` to prevent
  this, or `-Action RestoreShell` afterwards.

---

## Verifying by hand

```bash
# Is the flag live in the running process?            (R82.10)
ps -auxwww | grep [u]sim_launcher | grep -o "enable-poll-sleep=[0-9]"

# Is the parameter set?                               (R82.20+)
confp_cli get -p securexl.usim.adaptive_sleep.usim_with_sleep_enabled --format table

# What the cores are actually doing
top        # or htop - look at the per-core bars, not the summary

# NOT this - it cannot see the poll spin
cpstat os -f cpu
```

---

## References

- `sk180299` — Linux commands report a high CPU load average when SecureXL
  operates in User Space (UPPAK) mode
- `sk153832` — SecureXL modes, KPPAK and UPPAK
- Max Power 2026, Timothy Hall — origin of the poll sleep technique and the
  performance figures quoted above

---

## Licence

MIT. No warranty — this changes boot-time configuration on firewalls and
reboots them. Read it before you run it.
