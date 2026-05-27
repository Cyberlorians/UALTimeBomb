<#
.SYNOPSIS
    UAL TimeBomb - DISARM. Removes Everyone from the five SeDeny* logon rights and reboots.

.DESCRIPTION
    Reverses Arm-TimeBomb.ps1. Native secedit (no module deps).
    Idempotent: if already disarmed, exits 0 without rebooting.

    Effect:
      - For each of the five SeDeny* rights, removes the Everyone SID (S-1-1-0)
        from the assignee list. Other assignees (if any) are preserved.
      - Deletes sentinel C:\ProgramData\TimeBomb\bombdropped.txt
      - Force reboots in 15 seconds (recommended to flush LSA logon cache)

.NOTES
    State dir : C:\ProgramData\TimeBomb
    Sentinel  : C:\ProgramData\TimeBomb\bombdropped.txt
    Log       : C:\ProgramData\TimeBomb\disarm.log
#>

[CmdletBinding()]
param(
    [int]$RebootDelaySeconds = 15,
    [switch]$NoReboot
)

$ErrorActionPreference = 'Stop'
$StateDir  = 'C:\ProgramData\TimeBomb'
$Sentinel  = Join-Path $StateDir 'bombdropped.txt'
$LogFile   = Join-Path $StateDir 'disarm.log'
$DenyRights = @(
    'SeDenyBatchLogonRight',
    'SeDenyInteractiveLogonRight',
    'SeDenyNetworkLogonRight',
    'SeDenyRemoteInteractiveLogonRight',
    'SeDenyServiceLogonRight'
)

if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }

function Write-Log([string]$msg) {
    $line = "{0:u} {1}" -f (Get-Date).ToUniversalTime(), $msg
    Add-Content -Path $LogFile -Value $line
    Write-Host $line
}

function Get-EveryoneSid { 'S-1-1-0' }

if (-not ('TimeBomb.LsaRights' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace TimeBomb {
    public static class LsaRights {
        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES {
            public UInt32 Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public UInt32 Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern UInt32 LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES objectAttributes, UInt32 desiredAccess, out IntPtr policyHandle);

        [DllImport("advapi32.dll")]
        private static extern UInt32 LsaRemoveAccountRights(IntPtr policyHandle, byte[] accountSid, bool allRights, LSA_UNICODE_STRING[] userRights, UInt32 countOfRights);

        [DllImport("advapi32.dll")]
        private static extern UInt32 LsaClose(IntPtr objectHandle);

        [DllImport("advapi32.dll")]
        private static extern UInt32 LsaNtStatusToWinError(UInt32 status);

        private const UInt32 POLICY_CREATE_ACCOUNT = 0x00000010;
        private const UInt32 POLICY_LOOKUP_NAMES = 0x00000800;

        public static void RemoveRights(string sidValue, string[] rights) {
            IntPtr policyHandle = OpenPolicy();
            IntPtr[] buffers = null;
            try {
                byte[] sid = GetSidBytes(sidValue);
                LSA_UNICODE_STRING[] lsaRights = BuildRights(rights, out buffers);
                UInt32 status = LsaRemoveAccountRights(policyHandle, sid, false, lsaRights, (UInt32)lsaRights.Length);
                ThrowIfError(status, "LsaRemoveAccountRights");
            }
            finally {
                FreeBuffers(buffers);
                if (policyHandle != IntPtr.Zero) { LsaClose(policyHandle); }
            }
        }

        private static IntPtr OpenPolicy() {
            LSA_OBJECT_ATTRIBUTES attrs = new LSA_OBJECT_ATTRIBUTES();
            attrs.Length = (UInt32)Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            IntPtr policyHandle;
            UInt32 access = POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES;
            UInt32 status = LsaOpenPolicy(IntPtr.Zero, ref attrs, access, out policyHandle);
            ThrowIfError(status, "LsaOpenPolicy");
            return policyHandle;
        }

        private static byte[] GetSidBytes(string sidValue) {
            SecurityIdentifier sid = new SecurityIdentifier(sidValue);
            byte[] bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            return bytes;
        }

        private static LSA_UNICODE_STRING[] BuildRights(string[] rights, out IntPtr[] buffers) {
            LSA_UNICODE_STRING[] result = new LSA_UNICODE_STRING[rights.Length];
            buffers = new IntPtr[rights.Length];
            for (int i = 0; i < rights.Length; i++) {
                buffers[i] = Marshal.StringToHGlobalUni(rights[i]);
                result[i].Length = (UInt16)(rights[i].Length * 2);
                result[i].MaximumLength = (UInt16)((rights[i].Length + 1) * 2);
                result[i].Buffer = buffers[i];
            }
            return result;
        }

        private static void FreeBuffers(IntPtr[] buffers) {
            if (buffers == null) { return; }
            foreach (IntPtr buffer in buffers) {
                if (buffer != IntPtr.Zero) { Marshal.FreeHGlobal(buffer); }
            }
        }

        private static void ThrowIfError(UInt32 status, string operation) {
            if (status == 0) { return; }
            int win32 = (int)LsaNtStatusToWinError(status);
            throw new Win32Exception(win32, operation + " failed with Win32 error " + win32);
        }
    }
}
'@
}

function Export-SecPol([string]$path) {
    $null = secedit /export /cfg $path /quiet
    if (-not (Test-Path $path)) { throw "secedit /export failed: $path not produced" }
}

function Apply-SecPol([string]$infPath) {
    $sdb = [IO.Path]::ChangeExtension($infPath, '.sdb')
    $out = & secedit /configure /db $sdb /cfg $infPath /quiet 2>&1
    if ($LASTEXITCODE -ne 0) { throw "secedit /configure failed ($LASTEXITCODE): $out" }
    Remove-Item $sdb -Force -ErrorAction SilentlyContinue
}

function Parse-PrivilegeRights([string]$infPath) {
    $rights = @{}
    $inSection = $false
    foreach ($line in Get-Content -Path $infPath -Encoding Unicode) {
        if ($line -match '^\s*\[Privilege Rights\]\s*$') { $inSection = $true; continue }
        if ($inSection -and $line -match '^\s*\[') { break }
        if ($inSection -and $line -match '^\s*(Se\w+)\s*=\s*(.+)$') {
            $name = $Matches[1]
            $vals = $Matches[2].Trim() -split ','
            $sids = $vals | ForEach-Object { ($_ -replace '^\s*\*','').Trim() } | Where-Object { $_ }
            $rights[$name] = $sids
        }
    }
    return $rights
}

function Remove-EveryoneFromRight {
    param([hashtable]$Current, [string]$Right)
    $sid = Get-EveryoneSid
    $existing = @()
    if ($Current.ContainsKey($Right)) { $existing = $Current[$Right] }
    $kept = $existing | Where-Object { $_ -ne $sid }
    if (-not $kept) { return '' }   # empty value clears the right
    return ($kept | ForEach-Object { "*$_" }) -join ','
}

Write-Log "===== Disarm-TimeBomb starting ====="

$tmpDir = Join-Path $env:TEMP ("TimeBomb_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
$exportInf = Join-Path $tmpDir 'current.inf'
Export-SecPol -path $exportInf
$current = Parse-PrivilegeRights -infPath $exportInf

$everyoneSid = Get-EveryoneSid
$anyPresent = $false
foreach ($r in $DenyRights) {
    if ($current.ContainsKey($r) -and $current[$r] -contains $everyoneSid) { $anyPresent = $true; break }
}

if (-not $anyPresent -and -not (Test-Path $Sentinel)) {
    Write-Log "Already disarmed (no Everyone in deny rights, no sentinel). Exiting."
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    exit 0
}

Write-Log "Removing deny rights via LSA..."
[TimeBomb.LsaRights]::RemoveRights($everyoneSid, [string[]]$DenyRights)

# Verify
$verifyInf = Join-Path $tmpDir 'verify.inf'
Export-SecPol -path $verifyInf
$verify = Parse-PrivilegeRights -infPath $verifyInf
$ok = $true
foreach ($r in $DenyRights) {
    if ($verify.ContainsKey($r) -and $verify[$r] -contains $everyoneSid) {
        Write-Log "VERIFY FAIL: $r still contains Everyone"
        $ok = $false
    } else {
        Write-Log "VERIFY OK  : $r no longer contains Everyone"
    }
}

Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue

if (-not $ok) {
    Write-Log "Validation failed. Sentinel left in place. Not rebooting."
    exit 2
}

# Remove sentinel
if (Test-Path $Sentinel) {
    Remove-Item $Sentinel -Force
    Write-Log "Sentinel removed: $Sentinel"
}

if ($NoReboot) {
    Write-Log "NoReboot specified - skipping reboot."
} else {
    Write-Log "Scheduling reboot in $RebootDelaySeconds seconds."
    & shutdown.exe /r /f /t $RebootDelaySeconds /c "UAL TimeBomb disarmed - rebooting" | Out-Null
}

Write-Log "===== Disarm-TimeBomb complete ====="
exit 0
