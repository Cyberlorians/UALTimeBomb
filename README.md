# UAL TimeBomb Live Response

UAL TimeBomb is a Microsoft Sentinel and Microsoft Defender for Endpoint workflow that removes or restores local logon access on a Defender-onboarded Windows endpoint through MDE Live Response.

The workflow preserves the lockout behavior of a customer-provided access-control script, but replaces Tanium-specific delivery, modules, registry tags, and local activation timing with Sentinel watchlists, Logic Apps, and Defender Live Response.

This is intentionally disruptive. The ARM script grants Everyone (`S-1-1-0`) five deny-logon rights and reboots the endpoint. Test only on disposable, non-production devices with console, snapshot, or other out-of-band recovery.

## How It Works

Step by step:

1. Add a device to the ARM queue. An analyst adds a row to the `UALTimeBombARM` Sentinel watchlist with the MDE device ID.
2. Wait for the device. `Check-UALTimeBombQueue` runs on a recurrence and only picks rows whose device has recent `DeviceInfo` telemetry and no active Live Response action.
3. Trigger ARM. The queue checker adds `UALTimeBombDeploy`, calls `ualtimebomb-arm`, and marks the row `Dispatched`.
4. Run ARM on the endpoint. `ualtimebomb-arm` runs `Arm-TimeBomb.ps1` from the MDE Live Response Library.
5. Lock access. `Arm-TimeBomb.ps1` adds Everyone to five deny-logon rights, verifies the result, writes `C:\ProgramData\TimeBomb\bombdropped.txt`, logs off active sessions best effort, and reboots.
6. Mark armed. On success, `ualtimebomb-arm` removes the trigger tag and applies `UALTimeBombArmed`.
7. Restore access. An analyst adds a row to `UALTimeBombDisarm`. `ualtimebomb-disarm` runs `Disarm-TimeBomb.ps1` through Live Response.
8. Return to normal. On success, the disarm workflow removes UAL TimeBomb tags and marks the watchlist row `Disarmed`. It does not leave a success tag on the device.

The active workflow does not isolate, unisolate, contain, release containment, or perform any Defender device isolation action. ARM and DISARM are script-only Live Response workflows.

## Requirements

Before deployment, line up these permissions and artifacts.

### Who Deploys The ARM Templates

| Requirement | Why |
|---|---|
| Owner on the target Azure subscription, or equivalent rights to deploy Logic Apps and Sentinel watchlists. | The templates create or update Logic Apps and Sentinel watchlists. |
| Microsoft Sentinel workspace in the target tenant. | The queue model uses Sentinel watchlists as the analyst-controlled work queue. |
| Microsoft Defender for Endpoint enabled in the same tenant. | The workflows call Defender APIs and run Live Response. |

### Who Runs The Permission Script

| Requirement | Why |
|---|---|
| Microsoft Entra Global Administrator, Privileged Role Administrator, Cloud Application Administrator, or Application Administrator. | The script grants application roles to Logic App managed identities on Defender/XDR enterprise apps. |
| Azure permission to assign RBAC on the Sentinel workspace. | The queue and disarm identities need `Microsoft Sentinel Contributor` to read and update watchlists. |

### MDE Live Response Library Files

Upload these files to the MDE Live Response Library using the exact names below:

```text
Arm-TimeBomb.ps1
Disarm-TimeBomb.ps1
```

The Logic Apps call those names directly.

## Deployment

Deploy in this order. ARM and DISARM are separate so recovery can be deployed and permissioned before the ARM queue is enabled.

### Step 1. Upload Live Response Scripts

Upload the files from `src/LiveResponse` to the MDE Live Response Library:

```text
Arm-TimeBomb.ps1
Disarm-TimeBomb.ps1
```

### Step 2A. Deploy Commercial Azure

| Component | Deploy |
|---|---|
| ARM playbook (`ualtimebomb-arm`) | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCyberlorians%2FUALTimeBomb%2Fmain%2Fdeploy%2Fcommercial%2Fualtimebomb-arm.json) |
| DISARM playbook (`ualtimebomb-disarm`) | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCyberlorians%2FUALTimeBomb%2Fmain%2Fdeploy%2Fcommercial%2Fualtimebomb-disarm.json) |
| ARM queue checker (`Check-UALTimeBombQueue`) | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCyberlorians%2FUALTimeBomb%2Fmain%2Fdeploy%2Fcommercial%2Fcheck-ualtimebomb-queue.json) |

### Step 2B. Deploy Azure Government / GCC High

| Component | Deploy |
|---|---|
| ARM playbook (`ualtimebomb-arm`) | [![Deploy to Azure Government](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCyberlorians%2FUALTimeBomb%2Fmain%2Fdeploy%2Fgcch%2Fualtimebomb-arm.json) |
| DISARM playbook (`ualtimebomb-disarm`) | [![Deploy to Azure Government](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCyberlorians%2FUALTimeBomb%2Fmain%2Fdeploy%2Fgcch%2Fualtimebomb-disarm.json) |
| ARM queue checker (`Check-UALTimeBombQueue`) | [![Deploy to Azure Government](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCyberlorians%2FUALTimeBomb%2Fmain%2Fdeploy%2Fgcch%2Fcheck-ualtimebomb-queue.json) |

### Step 3. Grant Permissions

Run the permission helper after the templates deploy. Use `-WhatIf` first if you want to preview the RBAC and app-role grants.

```powershell
.\scripts\Grant-UALTimeBombPermissions.ps1 `
  -SubscriptionId '<subscription-guid>' `
  -PlaybookResourceGroup '<playbook-resource-group>' `
  -SentinelResourceGroup '<sentinel-resource-group>' `
  -SentinelWorkspaceName '<sentinel-workspace-name>'
```

### Step 4. Test Before Enabling The Queue

Keep `Check-UALTimeBombQueue` disabled until DISARM is deployed, permissioned, and tested. For a controlled test, add a single watchlist row and manually run the relevant Logic App recurrence.

### Manual Deployment Order

Use this order when deploying from templates instead of the buttons:

1. Upload the Live Response Library files from `src/LiveResponse`.
2. Deploy `deploy/commercial/ualtimebomb-arm.json`.
3. Deploy `deploy/commercial/ualtimebomb-disarm.json`.
4. Deploy `deploy/commercial/check-ualtimebomb-queue.json`.
5. Run `scripts/Grant-UALTimeBombPermissions.ps1` for the deployed managed identities.
6. Keep `Check-UALTimeBombQueue` disabled until DISARM is deployed, permissioned, and tested.
7. Add a controlled test row to `UALTimeBombARM` or `UALTimeBombDisarm`.
8. Manually run the relevant Logic App recurrence for a controlled test.

## Repository Layout

| Path | Purpose |
|---|---|
| `deploy/commercial` | Commercial Azure ARM templates and sample parameters. |
| `deploy/gcch` | Azure Government / GCC High templates and sample parameters. |
| `assets/watchlists` | Sentinel watchlist CSV schemas for ARM and DISARM queues. |
| `scripts` | Permission helper scripts for Logic App managed identities. |
| `src/LiveResponse` | PowerShell scripts uploaded to the MDE Live Response Library. |

## Watchlists

### `UALTimeBombARM`

The ARM queue lets an analyst add devices manually instead of relying on MDE tag search propagation.

Required analyst column:

| Column | Purpose |
|---|---|
| `MdatpDeviceId` | Defender for Endpoint machine ID. |

Optional analyst columns:

| Column | Purpose |
|---|---|
| `DeviceName` | Human-readable endpoint name. |
| `IncidentId` | Incident, case, change, or approval reference. |
| `Reason` | Reason for access lockout. |
| `RequestedBy` | Analyst or approval identity. |

System-managed columns:

| Column | Purpose |
|---|---|
| `EnqueuedTime` | Filled by the queue workflow when it first processes the row. |
| `Attempts` | Incremented by the workflow. |
| `Status` | `Pending`, `Retry`, `BlockedLiveResponse`, `Dispatched`, or terminal status. |
| `RetryAfterUtc` | UTC retry gate for stale or blocked devices. |
| `LastAttemptUtc` | Last processing time. |
| `LastError` | Last workflow error or readiness message. |
| `LastActionId` | Workflow run or Defender action ID. |

### `UALTimeBombDisarm`

The DISARM queue uses the same schema. A successful DISARM run removes UAL TimeBomb tags and marks the row `Disarmed`.

## Readiness Checks

The queue and disarm workflows use Defender Advanced Hunting `DeviceInfo` telemetry for freshness checks because the legacy machine entity endpoint can lag behind portal/device telemetry.

Readiness requires:

```text
OnboardingStatus = Onboarded
SensorHealthState = Active
Latest DeviceInfo timestamp within OnlineWindowMinutes
No Pending or InProgress Live Response action on the device
```

If a device is stale, offline, not onboarded, or blocked by another Live Response action, the workflow updates the watchlist row and waits for a later retry. It does not repeatedly probe Live Response just to check readiness.

## Tag Model

| Workflow | Trigger tag | Success state | Failure tag |
|---|---|---|---|
| ARM | `UALTimeBombDeploy` | `UALTimeBombArmed` | `UALTimeBombArmFailed` |
| DISARM | none for watchlist-driven restore | no UAL TimeBomb tags remain | `UALTimeBombDisarmFailed` |

The DISARM workflow removes `UALTimeBombArmed`, legacy `UALTimeBombDeployed`, `UALTimeBombRestore`, and `UALTimeBombDisarmed` best effort after the restore script succeeds.

## Required API Roles

The Logic Apps use system-assigned managed identities.

WindowsDefenderATP enterprise app:

| Workflow | Roles |
|---|---|
| `Check-UALTimeBombQueue` | `Machine.Read.All`, `Machine.ReadWrite.All` |
| `ualtimebomb-arm` | `Machine.Read.All`, `Machine.ReadWrite.All`, `Machine.LiveResponse` |
| `ualtimebomb-disarm` | `Machine.Read.All`, `Machine.ReadWrite.All`, `Machine.LiveResponse` |

Microsoft Threat Protection enterprise app:

| Workflow | Roles |
|---|---|
| `Check-UALTimeBombQueue` | `AdvancedHunting.Read.All` |
| `ualtimebomb-disarm` | `AdvancedHunting.Read.All` |

Sentinel workspace RBAC:

| Workflow | Role |
|---|---|
| `Check-UALTimeBombQueue` | `Microsoft Sentinel Contributor` |
| `ualtimebomb-disarm` | `Microsoft Sentinel Contributor` |

## Endpoint Effect

`Arm-TimeBomb.ps1` adds Everyone (`S-1-1-0`) to these local security policy rights:

```text
SeDenyBatchLogonRight
SeDenyInteractiveLogonRight
SeDenyNetworkLogonRight
SeDenyRemoteInteractiveLogonRight
SeDenyServiceLogonRight
```

Deny rights take precedence over allow rights. This can block local administrators too.

`Disarm-TimeBomb.ps1` removes only Everyone from those same rights and preserves any other existing assignees. It removes `C:\ProgramData\TimeBomb\bombdropped.txt` and reboots unless `-NoReboot` is supplied.

## Verification

For a controlled ARM test:

1. Choose a disposable Windows test device onboarded to MDE.
2. Confirm the device has recent `DeviceInfo` telemetry.
3. Add a `UALTimeBombARM` row with the MDE device ID.
4. Manually run `Check-UALTimeBombQueue`.
5. Verify the row becomes `Dispatched`.
6. Verify `ualtimebomb-arm` creates a successful Live Response action.
7. Verify the device reboots, `bombdropped.txt` exists, and all five deny rights include Everyone.

For a controlled DISARM test:

1. Add a `UALTimeBombDisarm` row with the same MDE device ID.
2. Manually run `ualtimebomb-disarm`.
3. Verify the row becomes `Disarmed`.
4. Verify `ualtimebomb-disarm` creates a successful Live Response action.
5. Verify `bombdropped.txt` is absent, all five deny rights no longer include Everyone, and no UAL TimeBomb tags remain on the device.

## Troubleshooting Quick Checks

### MDE API Calls Return 403

Run the permission helper again and confirm roles on both enterprise apps:

```text
WindowsDefenderATP:
  Machine.Read.All
  Machine.ReadWrite.All
  Machine.LiveResponse where required

Microsoft Threat Protection:
  AdvancedHunting.Read.All
```

### Queue Finds No Ready Devices

A running VM is not enough. The device must be onboarded to MDE, have `SensorHealthState = Active`, and have recent `DeviceInfo` telemetry.

### Live Response Does Not Start

Check for another `Pending` or `InProgress` Live Response action on the same device. The workflows intentionally block and retry rather than colliding with an existing session.

### Device Still Has UAL Tags After DISARM

Confirm the deployed DISARM template is version `1.7.6.0` or later. Earlier prototypes could leave a disarmed marker tag; the current workflow removes UAL TimeBomb tags after successful restore.
