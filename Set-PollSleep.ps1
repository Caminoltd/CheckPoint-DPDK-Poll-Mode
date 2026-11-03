<#
.SYNOPSIS
    Enables (or disables) UPPAK adaptive poll sleep on Check Point lab
    gateways, one at a time, with a safe sequential reboot.

    Written for the CPVS (VPN Specialist) R82.10 lab, but the gateway list is
    a parameter, so it works against any Gaia lab with the same problem.

.DESCRIPTION
    Runs on A-GUI. Connects to each gateway over SSH and picks the right
    mechanism automatically:

      R82.20+ : config_point parameter
                securexl.usim.adaptive_sleep.usim_with_sleep_enabled
                Applies live. No reboot needed.

      R82.10- : the --enable-poll-sleep=1 launch flag, set by editing the CPU
                test in /etc/ppk.boot/etc/dpdk_boot.sh. usim reads it only at
                startup, so a reboot is required.

    When a reboot is needed, members are done STRICTLY one at a time: standby
    first (detected via cphaprob), then a wait for it to come back and report a
    healthy cluster state, and only then the other member. The script will not
    touch the second gateway until the first is verified.

    LAB USE ONLY. Adaptive sleep on more than two cores is not supported, and
    on current releases a usim_x86 crash panics the whole gateway.

.PARAMETER Gateways
    Gateway IPs. Default 10.1.1.2 (A-GW-01) and 10.1.1.3 (A-GW-02), the Site
    Alpha cluster in the CPVS lab.

    198.51.100.1 is B-GW at Site Bravo, the third Check Point gateway, which
    has the same problem. It sits behind the Border-Router, so whether A-GUI
    can SSH to it depends on the policy - if it cannot be reached the script
    warns, skips it, and carries on with the Alpha cluster.

    C-GW at Site Charlie is a third-party firewall and is not applicable.

.PARAMETER User
    SSH user. Default admin.

.PARAMETER Action
    Check (default), Enable or Disable.

.PARAMETER NoReboot
    Apply the change but never reboot. For the script-edit method this leaves
    the change staged until the next boot, which the output states clearly.

.PARAMETER RebootTimeoutSec
    How long to wait for a member to come back. Default 600.

.EXAMPLE
    .\Set-PollSleep.ps1 -Action Check

.EXAMPLE
    .\Set-PollSleep.ps1 -Action Enable

.EXAMPLE
    .\Set-PollSleep.ps1 -Action Disable -Gateways 10.1.1.2

.NOTES
    Designed to work on a freshly launched cloud lab with no setup:

      * It tries ssh.exe with a key first, and if no key is present it falls
        back to PuTTY's plink and asks for the admin password once.
      * It forces hmac-sha2 MAC algorithms, working around the broken
        umac-128-etm implementation in the Windows OpenSSH client that fails
        with "Corrupted MAC on input" against Gaia.
      * In plink mode it accepts an uncached host key, since a new lab
        instance has never been connected to before.

    The one thing it cannot do for you is the shell. If the admin user is
    still in clish, run this once per gateway and the script will say so:
        set user admin shell /bin/bash
        save config

    The shipped dpdk_boot.sh test is `nproc --all` -eq 2, which enables sleep
    on 2-core boxes only. This script changes it to -ge 1 rather than the
    published -ne 2: -ne 2 would switch sleep OFF on a 2-core gateway, the one
    case the test was originally written for.
#>

[CmdletBinding()]
param(
    [string[]]$Gateways = @('10.1.1.2', '10.1.1.3', '198.51.100.1'),
    [string]$User = 'admin',

    [ValidateSet('Check', 'Enable', 'Disable', 'RestoreShell')]
    [string]$Action = 'Check',

    [switch]$NoReboot,
    [int]$RebootTimeoutSec = 600,

    # Force PuTTY's plink with password auth. Normally you do not need this:
    # the script tries ssh with a key first and falls back to plink on its own.
    [switch]$UsePlink,
    [string]$Password,

    # By default, if the login shell is clish the script switches it to bash
    # (set user <u> shell /bin/bash + save config) and carries on. Use this to
    # leave the gateway's configuration alone and stop instead.
    [switch]$NoShellFix,

    # Seconds to wait after the last reboot before taking the "after" CPU
    # reading. A gateway measured during policy load reports more CPU than it
    # did before the change. 0 reads immediately.
    [int]$SettleSec = 180
)

$ErrorActionPreference = 'Stop'

$Comment = 'Lab only: UPPAK poll sleep to cut SND CPU - set by Set-PollSleep.ps1'
# MACs: the Windows OpenSSH client has a broken umac-128-etm@openssh.com
# implementation and prefers it, which fails mid-session with
# "Corrupted MAC on input ... message authentication code incorrect".
# Listing the hmac-sha2 ETM variants first avoids it; umac stays last so it is
# still available if a future client build fixes the bug.
$SshMacs = 'hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,' +
           'hmac-sha2-256,hmac-sha2-512,umac-128-etm@openssh.com'

$SshOpts = @('-o', 'StrictHostKeyChecking=accept-new',
             '-o', 'ConnectTimeout=10',
             '-o', 'BatchMode=yes',
             '-o', 'LogLevel=ERROR',
             '-o', "MACs=$SshMacs")

function Write-Step { param([string]$m) Write-Host "  $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "  $m" -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host "  $m" -ForegroundColor Yellow }
function Write-Err  { param([string]$m) Write-Host "  $m" -ForegroundColor Red }
function Write-Head { param([string]$m)
    Write-Host ''
    Write-Host $m -ForegroundColor White
    Write-Host ('-' * 62) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Remote scripts
#
# Single-quoted here-strings only, so backticks and $ stay literal. Values are
# injected through @@TOKEN@@ placeholders rather than string interpolation -
# dpdk_boot.sh contains backticks, which PowerShell would eat.
# ---------------------------------------------------------------------------

$ScriptInspect = @'
P=securexl.usim.adaptive_sleep.usim_with_sleep_enabled
F=/etc/ppk.boot/etc/dpdk_boot.sh

VER=$(cpprod_util CPVER 2>/dev/null | head -1)
[ -z "$VER" ] && VER=$(ls -d /opt/CPppak-* 2>/dev/null | head -1 | sed 's#.*CPppak-##')
[ -z "$VER" ] && VER=unknown
echo "VERSION=$VER"

if command -v confp_cli >/dev/null 2>&1 && confp_cli get -p "$P" >/dev/null 2>&1; then
    echo "METHOD=confp"
    VAL=$(confp_cli get -p "$P" 2>/dev/null | grep -oiE 'true|false' | head -1)
    echo "CONFIGURED=$VAL"
elif [ -f "$F" ] && grep -q 'enable-poll-sleep' "$F"; then
    echo "METHOD=script"
    # "-eq 2" is the shipped default: sleep on 2-core boxes only, so OFF here.
    if grep -qE 'nproc --all. -eq 2' "$F"; then
        echo "CONFIGURED=false"
    else
        echo "CONFIGURED=true"
    fi
else
    echo "METHOD=unknown"
    echo "CONFIGURED=unknown"
fi

if ps -auxwww 2>/dev/null | grep -q '[u]sim_launcher.*enable-poll-sleep=1'; then
    echo "RUNNING=true"
elif ps -auxwww 2>/dev/null | grep -q '[u]sim_x86'; then
    echo "RUNNING=false"
else
    echo "RUNNING=nousim"
fi

HA=$(cphaprob state 2>&1)
ROLE=$(echo "$HA" | grep -i 'local' | grep -oiE 'ACTIVE|STANDBY|DOWN' | head -1)
if [ -z "$ROLE" ]; then
    # A single (non-cluster) gateway has no role to report. That is normal,
    # not a fault - do not confuse it with a cluster in trouble.
    if echo "$HA" | grep -qiE 'not started|not a cluster|disabled|no cluster|not configured'; then
        ROLE=single
    else
        ROLE=unknown
    fi
fi
echo "ROLE=$ROLE"

echo "CPUS=$(getconf _NPROCESSORS_ONLN 2>/dev/null)"
echo "UPTIME=$(cut -d' ' -f1 /proc/uptime | cut -d. -f1)"

# Per-core busy %, from two /proc/stat samples 2s apart.
#
# This is the ONLY view that measures poll sleep. It is the Linux view that
# sk180299 warns about: it includes the DPDK poll spin, which is precisely
# what we are toggling. cpstat and cpview deliberately report the SND's real
# work INSTEAD of the spin, so they do not move when poll sleep is toggled -
# a gateway with two cores pinned at 100% still reports single-digit CPU
# there. Do not use cpstat to measure this.
BUSY=$( { grep '^cpu[0-9]' /proc/stat; sleep 2; grep '^cpu[0-9]' /proc/stat; } | awk '
    !($1 in seen) { seen[$1]=1; for (i=2; i<=11; i++) p[$1","i]=$i+0; next }
    {
        tot=0; idle=0
        for (i=2; i<=11; i++) { d=($i+0)-p[$1","i]; tot+=d; if (i==5 || i==6) idle+=d }
        if (tot > 0) printf "%d\n", (100*(tot-idle)/tot)
    }' | sort -rn)

# Cores at 90%+ is the headline: 2 means the SNDs are spinning, 0 means they
# are sleeping. CORETOP shows the two busiest so the figure can be sanity
# checked rather than taken on trust.
echo "COREPINNED=$(echo "$BUSY" | awk '$1>=90' | wc -l | tr -d ' ')"
echo "CORETOP=$(echo "$BUSY" | head -2 | tr '\n' '/' | sed 's#/$##')"

# Kept for reference only - see the note above about why this does not move.
CPUSTAT=$(cpstat os -f cpu 2>/dev/null)
echo "CPUUSER=$(echo "$CPUSTAT"  | awk -F: '/User Time/   {gsub(/[ %]/,"",$2); print $2}')"
echo "CPUUSAGE=$(echo "$CPUSTAT" | awk -F: '/CPU Usage/   {gsub(/[ %]/,"",$2); print $2}')"
'@

$ScriptApplyTemplate = @'
P=securexl.usim.adaptive_sleep.usim_with_sleep_enabled
F=/etc/ppk.boot/etc/dpdk_boot.sh
MODE=@@MODE@@
WANT=@@WANT@@

# --- R82.20+ : config_point, applies live -----------------------------------
if command -v confp_cli >/dev/null 2>&1 && confp_cli get -p "$P" >/dev/null 2>&1; then
    confp_cli set -p "$P" -v "$WANT" -c "@@COMMENT@@" >/dev/null 2>&1 || {
        echo "RESULT=error"; echo "DETAIL=confp_cli set failed"; exit 1; }
    NOW=$(confp_cli get -p "$P" 2>/dev/null | grep -oiE 'true|false' | head -1)
    echo "RESULT=applied"
    echo "DETAIL=config_point now $NOW"
    echo "NEEDREBOOT=no"
    exit 0
fi

# --- R82.10- : launch flag in dpdk_boot.sh ----------------------------------
if [ ! -f "$F" ] || ! grep -q 'enable-poll-sleep' "$F"; then
    echo "RESULT=error"
    echo "DETAIL=no confp parameter and no enable-poll-sleep flag in $F"
    exit 2
fi

if grep -qE 'nproc --all. -eq 2' "$F"; then CUR=disabled; else CUR=enabled; fi

if [ "$MODE" = enable ] && [ "$CUR" = enabled ]; then
    echo "RESULT=nochange"
    echo "DETAIL=dpdk_boot.sh already enables poll sleep"
    echo "NEEDREBOOT=maybe"
    exit 0
fi
if [ "$MODE" = disable ] && [ "$CUR" = disabled ]; then
    echo "RESULT=nochange"
    echo "DETAIL=dpdk_boot.sh already at the shipped default"
    echo "NEEDREBOOT=maybe"
    exit 0
fi

[ -f "$F.labbk" ] || cp -p "$F" "$F.labbk"

# The address match on "nproc --all" keeps the substitution on that one line,
# and avoids putting a backtick in the pattern.
if [ "$MODE" = enable ]; then
    sed -i '/nproc --all/ s/-eq 2/-ge 1/; /nproc --all/ s/-ne 2/-ge 1/' "$F"
    EXPECT='-ge 1'
else
    sed -i '/nproc --all/ s/-ge 1/-eq 2/; /nproc --all/ s/-ne 2/-eq 2/' "$F"
    EXPECT='-eq 2'
fi

if grep -qE "nproc --all. $EXPECT" "$F"; then
    echo "RESULT=applied"
    echo "DETAIL=$(grep -nE 'nproc --all' "$F" | head -1 | tr -s ' ')"
    echo "NEEDREBOOT=yes"
else
    echo "RESULT=error"
    echo "DETAIL=sed did not match the expected test; backup restored"
    cp -p "$F.labbk" "$F"
    exit 3
fi
'@

$ScriptReboot = @'
nohup sh -c 'sleep 2; /sbin/reboot' >/dev/null 2>&1 &
echo REBOOTING
exit 0
'@

function Get-ApplyScript {
    param([Parameter(Mandatory)][ValidateSet('Enable', 'Disable')][string]$Mode)
    $want = if ($Mode -eq 'Enable') { 'true' } else { 'false' }
    return $ScriptApplyTemplate.
        Replace('@@MODE@@', $Mode.ToLower()).
        Replace('@@WANT@@', $want).
        Replace('@@COMMENT@@', $Comment)
}

# ---------------------------------------------------------------------------
# SSH plumbing
# ---------------------------------------------------------------------------

function Invoke-Gw {
    <#
      Runs a bash script on the gateway. The script is base64-encoded in
      transit, so no PowerShell/bash quoting collision is possible.

      stdout and stderr are captured separately via redirected temp files
      rather than 2>&1, because PowerShell turns native stderr into
      ErrorRecords and the reason for a failure is lost.

      Returns @{ Output = <string[]>; Err = <string>; Code = <int> }.
    #>
    param(
        [Parameter(Mandatory)][string]$Gateway,
        [Parameter(Mandatory)][string]$Script,
        [switch]$Raw
    )

    if ($Raw) {
        # Sent verbatim - used for clish commands, before bash is available.
        $remote = $Script
    }
    else {
        $b64    = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Script))
        $remote = "echo $b64 | base64 -d | bash"
    }

    $si = $null
    if ($UsePlink) {
        $exe     = $script:PlinkPath
        $cmdArgs = @('-ssh', '-l', $User)
        if ($Password) { $cmdArgs += @('-pw', $Password) }
        $cmdArgs += @($Gateway, $remote)

        # No -batch, and "y" on stdin: on a freshly launched lab the gateway's
        # host key is not cached yet, and -batch would simply refuse. This
        # accepts it, which is the right trade on a disposable lab network.
        $si = [IO.Path]::GetTempFileName()
        Set-Content -Path $si -Value "y`n" -NoNewline -Encoding ASCII
    }
    else {
        $exe     = 'ssh.exe'
        $cmdArgs = $SshOpts + @("$User@$Gateway", $remote)
    }

    $so = [IO.Path]::GetTempFileName()
    $se = [IO.Path]::GetTempFileName()
    try {
        $sp = @{
            FilePath               = $exe
            ArgumentList           = $cmdArgs
            NoNewWindow            = $true
            Wait                   = $true
            PassThru               = $true
            RedirectStandardOutput = $so
            RedirectStandardError  = $se
        }
        if ($si) { $sp['RedirectStandardInput'] = $si }

        $p   = Start-Process @sp
        $out = @(Get-Content $so -ErrorAction SilentlyContinue)
        $err = (Get-Content $se -Raw -ErrorAction SilentlyContinue)
        return @{ Output = $out; Err = "$err".Trim(); Code = $p.ExitCode }
    }
    finally {
        Remove-Item $so, $se -Force -ErrorAction SilentlyContinue
        if ($si) { Remove-Item $si -Force -ErrorAction SilentlyContinue }
    }
}

function Initialize-Transport {
    <#
      Works out how to reach the gateways with no prior setup:
      try ssh with a key, and if that fails for auth reasons fall back to
      PuTTY's plink with a password, asked for once.
    #>
    param([Parameter(Mandatory)][string]$Probe)

    if (-not $UsePlink) {
        if (Get-Command ssh.exe -ErrorAction SilentlyContinue) {
            $r   = Invoke-Gw -Gateway $Probe -Script 'echo SHELL_OK'
            $txt = (@($r.Output) + @($r.Err)) -join "`n"
            if ($r.Code -eq 0 -and $txt -match 'SHELL_OK') {
                Write-Ok 'Using ssh.exe with key authentication.'
                return
            }
            if ($txt -notmatch 'Permission denied|publickey|No supported authentication') {
                return   # something else is wrong; let Test-GwPrereq explain it
            }
            Write-Step 'No usable SSH key - falling back to PuTTY plink with a password.'
        }
        else {
            Write-Step 'ssh.exe not found - using PuTTY plink.'
        }
        $script:UsePlink = $true
    }

    # Locate plink: PATH first, then the usual install folders.
    $script:PlinkPath = (Get-Command plink.exe -ErrorAction SilentlyContinue).Source
    if (-not $script:PlinkPath) {
        foreach ($c in @("$env:ProgramFiles\PuTTY\plink.exe",
                         "${env:ProgramFiles(x86)}\PuTTY\plink.exe",
                         "$env:LOCALAPPDATA\Programs\PuTTY\plink.exe")) {
            if (Test-Path $c) { $script:PlinkPath = $c; break }
        }
    }
    if (-not $script:PlinkPath) {
        throw ("Need either key-based SSH or plink.exe, and neither is available.`n" +
               "  Install PuTTY, or set up an SSH key for $User on the gateways.")
    }

    if (-not $Password) {
        $sec = Read-Host "  Password for '$User' on the gateways" -AsSecureString
        $script:Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                               [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
    }
}

function Test-GwPort {
    param([Parameter(Mandatory)][string]$Gateway, [int]$TimeoutMs = 3000)
    try {
        $c  = New-Object Net.Sockets.TcpClient
        $ar = $c.BeginConnect($Gateway, 22, $null, $null)
        $ok = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($ok) { $c.EndConnect($ar) }
        $c.Close()
        return $ok
    }
    catch { return $false }
}

function Save-GwConfig {
    <#
      Runs "save config" through clish. Must be called from a bash session,
      and WITHOUT -Raw so the quotes survive Start-Process.
    #>
    param([Parameter(Mandatory)][string]$Gateway)

    $r = Invoke-Gw -Gateway $Gateway -Script 'clish -c "save config" 2>&1; echo RC=$?'
    $t = ((@($r.Output) + @($r.Err)) -join ' ').Trim()

    if ($t -notmatch 'RC=0' -or $t -match 'Usage|not found|CLINFR|Failed|read.only|lock') {
        throw ("'save config' failed on ${Gateway}: $t`n" +
               "  Without it the shell change reverts at the next reboot.`n" +
               "  Run this on the gateway, in expert mode:`n" +
               "      clish -c `"save config`"")
    }
    Write-Ok 'Configuration saved.'
}

function Repair-GwShell {
    <#
      When clish is the login shell it executes the remote command string as a
      clish command - which is exactly what we need to change the shell. Each
      connection is a fresh login, so the next one lands in bash.
    #>
    param([Parameter(Mandatory)][string]$Gateway)

    Write-Step "$User shell is clish on $Gateway - switching it to bash ..."

    # Step 1, in clish: change the shell. This takes effect IMMEDIATELY, so
    # every connection after this one lands in bash.
    $r = Invoke-Gw -Gateway $Gateway -Script "set user $User shell /bin/bash" -Raw
    $t = ((@($r.Output) + @($r.Err)) -join ' ').Trim()
    if ($t -match 'CLINFR|Invalid command|Failed|read.only|lock') {
        throw ("Could not change the shell on ${Gateway}: $t`n" +
               "  If that mentions a configuration lock, close other clish/PuTTY sessions`n" +
               "  logged in as $User. Otherwise run these on the gateway, in clish:`n" +
               "      set user $User shell /bin/bash`n" +
               "      save config")
    }

    # The shell has already changed, so this connection is bash: "save config"
    # has to go through clish. Without it the change lives only in the running
    # config and reverts at the next reboot.
    Save-GwConfig -Gateway $Gateway

    # Verify both halves: bash is live, and the passwd entry agrees.
    $v  = Invoke-Gw -Gateway $Gateway -Script "echo SHELL_OK; getent passwd $User | cut -d: -f7"
    $vt = (@($v.Output) + @($v.Err)) -join ' '
    if ($vt -notmatch 'SHELL_OK') {
        throw "Shell change did not take effect on ${Gateway}: $vt"
    }
    if ($vt -notmatch '/bin/bash') {
        Write-Warn "bash works, but the passwd entry still reads: $vt"
    }
    Write-Ok 'Shell set to bash and saved via clish -c.'
}

function Restore-GwShell {
    <#
      Puts the login shell back to clish (/etc/cli.sh). Run from bash, so the
      save has to go through clish -c BEFORE the shell flips back.
    #>
    param([Parameter(Mandatory)][string]$Gateway)

    Write-Step "Restoring $User shell to clish on $Gateway ..."
    # Both in one bash session, and the save BEFORE the shell flips back -
    # once it is clish again, clish -c is no longer reachable from here.
    $script = 'clish -c "set user ' + $User + ' shell /etc/cli.sh" 2>&1; ' +
              'clish -c "save config" 2>&1; echo RC=$?'
    $r = Invoke-Gw -Gateway $Gateway -Script $script
    $t = ((@($r.Output) + @($r.Err)) -join ' ').Trim()

    if ($t -notmatch 'RC=0' -or $t -match 'Usage|not found|CLINFR|Failed|read.only|lock') {
        throw ("Could not restore the shell on ${Gateway}: $t`n" +
               "  Run on the gateway, in clish:`n" +
               "      set user $User shell /etc/cli.sh`n" +
               "      save config")
    }
    Write-Ok 'Shell restored to clish and config saved.'
}

function Test-GwPrereq {
    param(
        [Parameter(Mandatory)][string]$Gateway,
        [switch]$Retry
    )

    if (-not (Test-GwPort -Gateway $Gateway)) {
        throw "$Gateway is not answering on TCP 22."
    }
    $r   = Invoke-Gw -Gateway $Gateway -Script 'echo SHELL_OK'
    $all = (@($r.Output) + @($r.Err)) -join "`n"

    if ($r.Code -eq 0 -and $all -match 'SHELL_OK') { return }

    # clish as the login shell is the normal state of a fresh lab image, so
    # fix it rather than making the operator do it on every gateway.
    if (-not $Retry -and -not $NoShellFix -and $all -match 'CLINFR|Invalid command') {
        Repair-GwShell -Gateway $Gateway
        Test-GwPrereq -Gateway $Gateway -Retry
        return
    }

    # Work out WHY, so the message is actionable.
    $why = switch -Regex ($all) {
        'Corrupted MAC|message authentication code incorrect' {
            "The Windows OpenSSH client's umac-128-etm implementation is broken.`n" +
            "      The script already forces hmac-sha2 MACs, so if you still see this,`n" +
            "      use PuTTY instead:`n" +
            "          .\Set-PollSleep.ps1 -UsePlink -Action Check"
            break
        }
        'Permission denied|publickey|No supported authentication' {
            if ($UsePlink) { 'Authentication failed. Check -Password, or the account.' }
            else {
                "No usable SSH key for $User@$Gateway.`n" +
                "      Either set up key auth, or re-run with PuTTY:`n" +
                "          .\Set-PollSleep.ps1 -UsePlink -Password '<admin password>' -Action Check"
            }
            break
        }
        'Host key verification|server.s host key is not cached' {
            "Host key not trusted/cached. Connect once interactively first:`n" +
            "          ssh $User@$Gateway      (or open a PuTTY session to it)"
            break
        }
        'Unknown command|CLINFR|Invalid command|clish' {
            if ($NoShellFix) {
                "The $User shell is clish, not bash, and -NoShellFix was given.`n" +
                "      On the gateway, in clish:`n" +
                "          set user $User shell /bin/bash`n" +
                "          save config"
            }
            else {
                "The $User shell is still clish after the automatic fix.`n" +
                "      Set it by hand on the gateway, in clish:`n" +
                "          set user $User shell /bin/bash`n" +
                "          save config"
            }
            break
        }
        '^\s*$' {
            if ($UsePlink) { 'plink produced no output. Is plink.exe on PATH?' }
            else {
                "ssh produced no output at all, which usually means authentication`n" +
                "      failed silently under BatchMode. Try this by hand to see the reason:`n" +
                "          ssh -o BatchMode=yes $User@$Gateway `"echo SHELL_OK`""
            }
            break
        }
        default { 'Unexpected response.' }
    }

    throw ("Could not run a shell command on $Gateway (exit code $($r.Code)).`n" +
           "  Reason: $why`n" +
           "  stdout: $(@($r.Output) -join ' ')`n" +
           "  stderr: $($r.Err)")
}

function ConvertTo-Map {
    param([string[]]$Lines)
    $m = @{}
    foreach ($l in $Lines) {
        if ("$l" -match '^([A-Z]+)=(.*)$') { $m[$Matches[1]] = $Matches[2].Trim() }
    }
    return $m
}

function Get-GwState {
    param([Parameter(Mandatory)][string]$Gateway)
    $r = Invoke-Gw -Gateway $Gateway -Script $ScriptInspect
    if ($r.Code -ne 0) {
        throw "Inspection failed on ${Gateway} (exit $($r.Code)): $(@($r.Output) -join ' ') $($r.Err)"
    }
    $m = ConvertTo-Map -Lines $r.Output
    $m['Gateway'] = $Gateway
    return $m
}

function Show-GwState {
    param([hashtable]$S)
    $run = switch ($S.RUNNING) {
        'true'   { 'poll sleep ACTIVE' }
        'false'  { 'poll sleep not active' }
        'nousim' { 'usim not running (KPPAK?)' }
        default  { 'unknown' }
    }
    $cpu = if ($null -ne $S.COREPINNED) { "pinned:$($S.COREPINNED)/$($S.CPUS) top:$($S.CORETOP)%" }
           else { 'pinned:?' }
    Write-Host ("  {0,-14} {1,-9} {2,-8} {3,-24} set:{4,-7} {5}" -f `
        $S.Gateway, $S.VERSION, $S.ROLE, $cpu, $S.CONFIGURED, $run)
}

function Wait-GwReturn {
    param([Parameter(Mandatory)][string]$Gateway, [int]$TimeoutSec)

    $sw = [Diagnostics.Stopwatch]::StartNew()

    Write-Step 'Waiting for SSH to drop ...'
    while ($sw.Elapsed.TotalSeconds -lt 120) {
        if (-not (Test-GwPort -Gateway $Gateway -TimeoutMs 2000)) { break }
        Start-Sleep -Seconds 3
    }

    Write-Step 'Waiting for the gateway to come back ...'
    $back    = $false
    $state   = $null
    $lastErr = $null
    $tries   = 0
    $reFixed = $false
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        Start-Sleep -Seconds 10
        if (-not (Test-GwPort -Gateway $Gateway -TimeoutMs 3000)) {
            Write-Host '.' -NoNewline -ForegroundColor DarkGray
            continue
        }
        try {
            $state = Get-GwState -Gateway $Gateway
            $up = 0; [void][int]::TryParse($state.UPTIME, [ref]$up)
            if ($up -gt 0 -and $up -lt 3600) { $back = $true; break }
            $lastErr = "inspection returned UPTIME='$($state.UPTIME)'"
        }
        catch {
            # Early in the boot this is normal. Later it is the real problem,
            # so keep it and show it - do not let the dots hide the reason.
            $lastErr = $_.Exception.Message
        }

        $tries++
        if ($tries % 6 -eq 0 -and $lastErr) {
            Write-Host ''
            Write-Warn ("Port 22 is open but inspection is failing after " +
                        "$([int]$sw.Elapsed.TotalSeconds)s: $lastErr")
            if ($lastErr -match 'CLINFR|Invalid command') {
                Write-Warn "The $User shell went back to clish across the reboot - 'save config' did not stick."
                if (-not $NoShellFix -and -not $reFixed) {
                    $reFixed = $true
                    try { Repair-GwShell -Gateway $Gateway }
                    catch { Write-Warn $_.Exception.Message }
                }
            }
        }
        Write-Host '.' -NoNewline -ForegroundColor DarkGray
    }
    Write-Host ''

    if (-not $back) {
        throw ("$Gateway did not come back within $TimeoutSec seconds.`n" +
               "  Last error: $lastErr`n" +
               "  The gateway itself may be fine - check it before touching the other member.")
    }

    Write-Step 'Waiting for a healthy state ...'
    for ($i = 0; $i -lt 30; $i++) {
        $state = Get-GwState -Gateway $Gateway
        if (@('ACTIVE', 'STANDBY') -contains $state.ROLE) {
            Write-Ok "Back up, uptime $($state.UPTIME)s, cluster state $($state.ROLE)"
            return $state
        }
        if ($state.ROLE -eq 'single') {
            Write-Ok "Back up, uptime $($state.UPTIME)s, single gateway (not a cluster member)"
            return $state
        }
        Start-Sleep -Seconds 10
    }
    Write-Warn "Back up, but the state reads '$($state.ROLE)'. Check cphaprob state before continuing."
    return $state
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Head "UPPAK poll sleep - $Action"

if (-not (Test-GwPort -Gateway $Gateways[0])) {
    throw "$($Gateways[0]) is not answering on TCP 22. Is the lab fully started?"
}

Initialize-Transport -Probe $Gateways[0]

if ($Action -eq 'RestoreShell') {
    foreach ($gw in $Gateways) {
        $p = Invoke-Gw -Gateway $gw -Script 'echo SHELL_OK'
        if (((@($p.Output) + @($p.Err)) -join ' ') -match 'SHELL_OK') {
            Restore-GwShell -Gateway $gw
        }
        else {
            Write-Step "$gw is already using clish - nothing to do."
        }
    }
    Write-Host ''
    return
}

# Inspect everything before changing anything. A gateway that cannot be
# reached is skipped rather than fatal: B-GW sits behind the Border-Router, so
# whether A-GUI can SSH to it depends on the policy of the day.
$states  = @()
$skipped = @()
foreach ($gw in $Gateways) {
    Write-Step "Inspecting $gw ..."
    try {
        Test-GwPrereq -Gateway $gw
        $states += Get-GwState -Gateway $gw
    }
    catch {
        Write-Warn "Skipping ${gw}: $($_.Exception.Message.Split("`n")[0])"
        $skipped += $gw
    }
}
if (-not $states) { throw 'No gateways could be reached.' }

Write-Host ''
Write-Host '  Current state' -ForegroundColor White
foreach ($s in $states) { Show-GwState -S $s }

if ($Action -eq 'Check') {
    Write-Host ''
    Write-Host '  Nothing changed. Re-run with -Action Enable or -Action Disable.' -ForegroundColor Gray
    Write-Host ''
    return
}

$wanted = if ($Action -eq 'Enable') { 'true' } else { 'false' }

# Reboot in the order given, so the FIRST gateway listed goes first. In a
# cluster the member rebooted LAST ends up standby, so putting A-GW-01 at the
# head of -Gateways leaves A-GW-01 active when the run finishes.
$ordered = @($states | Sort-Object @{ Expression = { $Gateways.IndexOf($_.Gateway) } })
Write-Step ("Reboot order: " + (($ordered | ForEach-Object { $_.Gateway }) -join ' -> '))

$applyScript = Get-ApplyScript -Mode $Action
$rebooted = @()

foreach ($s in $ordered) {
    $gw = $s.Gateway
    Write-Head "$gw   ($($s.VERSION), $($s.ROLE), $($s.METHOD) method)"

    if ($s.CONFIGURED -eq $wanted -and $s.RUNNING -eq $wanted) {
        Write-Ok 'Already in the requested state and active. Skipping.'
        continue
    }

    $r = Invoke-Gw -Gateway $gw -Script $applyScript
    $m = ConvertTo-Map -Lines $r.Output

    switch ($m.RESULT) {
        'applied'  { Write-Ok   "Applied: $($m.DETAIL)" }
        'nochange' { Write-Step  $m.DETAIL }
        default {
            Write-Err "Failed on ${gw}: $($m.DETAIL)"
            Write-Err ($r.Output -join "`n  ")
            throw 'Stopping. The other member has not been touched.'
        }
    }

    if ($m.NEEDREBOOT -eq 'no') {
        Start-Sleep -Seconds 3
        $after = Get-GwState -Gateway $gw
        if ($after.RUNNING -eq $wanted) {
            Write-Ok 'Live - no reboot needed.'
        }
        else {
            Write-Warn "config_point set, but usim reports RUNNING=$($after.RUNNING). A reboot may be needed."
        }
        continue
    }

    if ($NoReboot) {
        Write-Warn 'Change staged. It takes effect at the next reboot (-NoReboot was given).'
        continue
    }

    # Unconditional: the shell may already have been set to bash by an earlier
    # run that failed before saving, in which case nothing above would have
    # saved it and it would revert across this reboot.
    Write-Step 'Saving configuration before reboot ...'
    Save-GwConfig -Gateway $gw

    Write-Step "Rebooting $gw ..."
    Invoke-Gw -Gateway $gw -Script $ScriptReboot | Out-Null
    $after = Wait-GwReturn -Gateway $gw -TimeoutSec $RebootTimeoutSec
    $rebooted += $gw

    if ($after.RUNNING -eq $wanted) {
        $word = if ($wanted -eq 'true') { 'ENABLED' } else { 'DISABLED' }
        Write-Ok "Verified: usim is running with poll sleep $word."
    }
    else {
        Write-Warn "After reboot usim reports RUNNING=$($after.RUNNING), expected $wanted."
        Write-Warn 'Check dpdk_boot.sh on this member before continuing to the other.'
        throw 'Stopping. The other member has not been touched.'
    }
}

# A gateway measured seconds after boot is still loading policy, so its CPU
# reads HIGHER than before the change and the comparison looks wrong. Let the
# most recently rebooted member settle before taking the "after" figures.
if ($rebooted -and $SettleSec -gt 0) {
    Write-Host ''
    Write-Step "Letting the gateways settle for $SettleSec s before the final CPU reading ..."
    Start-Sleep -Seconds $SettleSec
}

Write-Head 'Final state'
$after = @()
foreach ($s in $states) {
    $a = Get-GwState -Gateway $s.Gateway
    $after += $a
    Show-GwState -S $a
}

# Before/after on Check Point's own CPU figures - the same numbers
# "cpstat os -f cpu" gives from the management server.
Write-Host ''
if (-not $rebooted.Count) {
    # Nothing was changed, so the two readings are the same settled state
    # sampled twice. Printing them as "before and after" would invite someone
    # to read sampling jitter as an effect.
    Write-Host '  Cores at 90%+ - nothing changed this run, so these are two' -ForegroundColor White
    Write-Host '  samples of the same state, not a before/after comparison.' -ForegroundColor White
    Write-Host ("  {0,-14} {1,-26} {2}" -f 'Gateway', 'Sample 1 (pinned, top 2)', 'Sample 2 (pinned, top 2)') -ForegroundColor Gray
}
else {
    Write-Host '  Cores at 90%+ before and after (from /proc/stat)' -ForegroundColor White
    Write-Host ("  {0,-14} {1,-26} {2}" -f 'Gateway', 'Before (pinned, top 2)', 'After (pinned, top 2)') -ForegroundColor Gray
}
foreach ($b in $states) {
    $a = $after | Where-Object { $_.Gateway -eq $b.Gateway } | Select-Object -First 1
    Write-Host ("  {0,-14} {1,-26} {2}" -f $b.Gateway,
        "$($b.COREPINNED) of $($b.CPUS)  [$($b.CORETOP)%]",
        "$($a.COREPINNED) of $($a.CPUS)  [$($a.CORETOP)%]")
}
Write-Host ''
Write-Host '  cpstat/cpview do NOT move when poll sleep is toggled - they report the' -ForegroundColor DarkGray
Write-Host '  SND''s real work, not the poll spin (sk180299). Use the figures above.' -ForegroundColor DarkGray
if ($skipped) {
    Write-Host ''
    Write-Warn "Not reached: $($skipped -join ', ')"
}

Write-Host ''
if ($rebooted.Count) { Write-Host "  Rebooted: $($rebooted -join ', ')" -ForegroundColor Gray }
Write-Host '  Verify on a gateway with:' -ForegroundColor Gray
Write-Host '    ps -auxwww | grep [u]sim_launcher | grep -o "enable-poll-sleep=[0-9]"' -ForegroundColor DarkGray
Write-Host '    cphaprob state' -ForegroundColor DarkGray
Write-Host ''
