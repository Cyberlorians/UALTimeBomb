# UAL TimeBomb Validation Notes

This file records public-safe validation status for the UAL TimeBomb Live Response workflow. It intentionally avoids tenant IDs, device IDs, subscription IDs, and customer-specific identifiers.

## Current Workflow Findings

- DISARM behavior was corrected so successful restore does not leave a success marker tag. It removes UAL TimeBomb tags and returns the device to normal tag state.
- ARM and DISARM active templates are script-only Live Response workflows. They do not perform Defender isolate, unisolate, containment, or release-containment actions.
- ARM queue and DISARM readiness use Defender Advanced Hunting `DeviceInfo` telemetry instead of stale machine entity `lastSeen` values.
- Advanced Hunting readiness requires `AdvancedHunting.Read.All` on the Microsoft Threat Protection enterprise app for the queue and DISARM managed identities.

## Completed Validation

### DISARM

- A previously armed Windows lab endpoint was restored through `ualtimebomb-disarm`.
- MDE Live Response returned `Succeeded`.
- The Sentinel watchlist row moved to `Disarmed`.
- MDE UAL TimeBomb tags were absent after completion.
- On-box verification confirmed `C:\ProgramData\TimeBomb\bombdropped.txt` was absent.
- On-box verification confirmed Everyone (`S-1-1-0`) was absent from all five deny-logon rights.

### ARM Queue And ARM Script

- `Check-UALTimeBombQueue` successfully processed an eligible ARM row using Advanced Hunting readiness.
- The queue row moved to `Dispatched`.
- `ualtimebomb-arm` successfully launched `Arm-TimeBomb.ps1` through Live Response on an active Windows lab endpoint.
- MDE Live Response returned `Succeeded` for that endpoint.
- MDE applied `UALTimeBombArmed` after script success.
- On-box verification confirmed `C:\ProgramData\TimeBomb\bombdropped.txt` existed.
- On-box verification confirmed Everyone (`S-1-1-0`) was present on all five deny-logon rights.

## In-Progress / Watch Items

- One ARM Live Response action on an earlier lab endpoint remained in `Pending` with command status `Created` while the Logic App continued polling. The endpoint was running, Defender services were running, and MDE gateway connectivity succeeded from the VM. Treat this as an MDE Live Response service queue/start delay, not a script failure, unless it later times out.
- A second lab endpoint completed ARM successfully. Its follow-up DISARM restore was queued and entered `Pending` Live Response state while being monitored.

## Next Checks

1. Recheck any pending Live Response actions until each reaches `Succeeded`, `Failed`, `Cancelled`, or the Logic App timeout path.
2. For any ARM success, verify both MDE tags and on-box deny rights.
3. For any DISARM success, verify no UAL TimeBomb tags remain, `bombdropped.txt` is absent, and Everyone is absent from all five deny-logon rights.
4. Keep `Check-UALTimeBombQueue` disabled except during controlled queue tests.
