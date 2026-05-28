# UAL TimeBomb Validation Notes

This file records public-safe validation status for the UAL TimeBomb Live Response workflow. It intentionally avoids tenant IDs, device IDs, subscription IDs, and customer-specific identifiers.

## Current Workflow Findings

- DISARM behavior was corrected so successful restore does not leave a success marker tag. It removes UAL TimeBomb tags and returns the device to normal tag state.
- ARM and DISARM active templates are script-only Live Response workflows. They do not perform Defender isolate, unisolate, containment, or release-containment actions.
- ARM queue and DISARM readiness use Defender Advanced Hunting `DeviceInfo` telemetry instead of stale machine entity `lastSeen` values.
- Advanced Hunting readiness requires `AdvancedHunting.Read.All` on the Microsoft Threat Protection enterprise app for the queue and DISARM managed identities.

## Completed Validation

### ARM Retest - May 28, 2026

- Target endpoint: `usm262346`.
- Baseline before ARM was clean: no UAL TimeBomb tags, `C:\ProgramData\TimeBomb\bombdropped.txt` absent, and Everyone (`S-1-1-0`) absent from all five deny-logon rights.
- A stale prior ARM Live Response action was cancelled before retest: `fe6c1708-6afe-49c8-b3dc-7955c9e5d388`.
- `ualtimebomb-arm` was triggered directly with the MDE device ID because the ARM watchlist row update path was blocked during manual retest.
- ARM Logic App run `08584216173169501543781917866CU59` succeeded.
- MDE Live Response action `8d70bcd8-5969-4446-86e7-21e6eb05b7fa` succeeded and `Arm-TimeBomb.ps1` command status was `Completed`.
- MDE applied `UALTimeBombArmed`.
- On-box verification confirmed `C:\ProgramData\TimeBomb\bombdropped.txt` existed.
- On-box verification confirmed Everyone (`S-1-1-0`) was present on all five deny-logon rights.
- Current endpoint state after this retest: armed.

### Queue ARM Test - May 28, 2026

- Target endpoint: `attackiq01`.
- Baseline before queue test was clean: no UAL TimeBomb tags, `C:\ProgramData\TimeBomb\bombdropped.txt` absent, and Everyone (`S-1-1-0`) absent from all five deny-logon rights.
- ARM watchlist staged with exactly one row for the target in `Pending` with `Attempts=0`.
- `Check-UALTimeBombQueue` was enabled for a single recurrence, manually triggered, then disabled again immediately after dispatch.
- Queue Logic App run succeeded and moved the watchlist row to `Status=Dispatched`, `Attempts=1`, with `LastActionId` populated.
- `ualtimebomb-arm` was invoked by the queue and succeeded end-to-end.
- MDE Live Response action requestor was `ualtimebomb-arm`, `ScriptName=Arm-TimeBomb.ps1`, action status `Succeeded`, command status `Completed`.
- On-box verification confirmed `C:\ProgramData\TimeBomb\bombdropped.txt` existed.
- On-box verification confirmed Everyone (`S-1-1-0`) was present on all five deny-logon rights.
- MDE machine tag application lagged after script success; tag write was not yet reflected on the machine entity at verification time. Live Response action success confirms ARM payload applied regardless of tag propagation.
- `Check-UALTimeBombQueue` returned to `Disabled` after the test.
- Current endpoint state after this test: armed.

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
- A second lab endpoint completed ARM successfully. On-box verification confirmed `bombdropped.txt` existed and Everyone was present in all five deny-logon rights. Its follow-up DISARM restore was queued and entered `Pending` Live Response state while being monitored.
- Both pending Live Response actions had command status `Created` with no command start time while the affected VMs reported running Defender services and successful MDE gateway connectivity. The Logic Apps were left running to follow their normal polling/timeout paths.
- `Check-UALTimeBombQueue` was disabled again after each controlled manual queue run.

## Next Checks

1. Recheck any pending Live Response actions until each reaches `Succeeded`, `Failed`, `Cancelled`, or the Logic App timeout path.
2. For any ARM success, verify both MDE tags and on-box deny rights.
3. For any DISARM success, verify no UAL TimeBomb tags remain, `bombdropped.txt` is absent, and Everyone is absent from all five deny-logon rights.
4. Keep `Check-UALTimeBombQueue` disabled except during controlled queue tests.
