# Azure Government / GCC High Deployment

This folder contains the Azure Government / GCC High variants of the UAL
TimeBomb ARM templates. They are deployment-button-compatible with the
`portal.azure.us` portal and ship with government-cloud defaults for ARM,
Defender for Endpoint, and Microsoft Security Advanced Hunting endpoints.

For end-to-end deployment, permission, and verification steps, follow the
top-level [README](../../README.md) and use the Government / GCC High deploy
buttons. The steps and parameter fields are identical to commercial; only the
cloud-specific endpoint defaults differ.

## Cloud Defaults

| Parameter | GCC High Default |
|---|---|
| `DefenderApiBaseUri` | `https://api-gov.securitycenter.microsoft.us` |
| `DefenderApiAudience` | `https://api-gov.securitycenter.microsoft.us` |
| `AdvancedHuntingApiBaseUri` | `https://api-gov.security.microsoft.us` |
| `AdvancedHuntingApiAudience` | `https://api-gov.security.microsoft.us` |
| `ArmBaseUri` | `https://management.usgovcloudapi.net` |
| `ArmAudience` | `https://management.usgovcloudapi.net/` |

## Regular GCC (Not GCC High)

Regular GCC tenants use different Defender host names than GCC High. Confirm
the values for your specific cloud against Microsoft's published service
endpoint documentation before deploying. Common GCC values:

| Parameter | Regular GCC Default |
|---|---|
| `DefenderApiBaseUri` | `https://api-gcc.securitycenter.microsoft.us` |
| `DefenderApiAudience` | `https://api-gcc.securitycenter.microsoft.us` |

ARM and Advanced Hunting endpoints on regular GCC typically still use the
public-cloud hosts (`https://management.azure.com`,
`https://api.security.microsoft.com`). Validate before deploy.

## Portal And CLI

```text
Azure portal:        https://portal.azure.us
Microsoft Defender:  https://security.microsoft.us
Microsoft Entra:     https://entra.microsoft.us
Azure CLI:           az cloud set --name AzureUSGovernment ; az login
```

## Permission Helper

[scripts/Grant-UALTimeBombPermissions.ps1](../../scripts/Grant-UALTimeBombPermissions.ps1)
is cloud-aware. It reads the active cloud from `az cloud show` and
automatically targets the correct Microsoft Graph endpoint
(`https://graph.microsoft.us`) and Defender enterprise app in the Government
tenant. Run it after `az cloud set --name AzureUSGovernment` and `az login`.

## Live Response Library Upload Fallback

The GCC High Defender portal sometimes rejects Live Response Library uploads
with the generic error `Failed to upload file — A problem occurred while
running the command.` If this happens, upload `Arm-TimeBomb.ps1` and
`Disarm-TimeBomb.ps1` via the MDE API:

```text
POST https://api-gov.securitycenter.microsoft.us/api/libraryfiles
Content-Type: multipart/form-data
```

Register a temporary Entra app, grant it `Machine.LiveResponse` and
`Library.Manage` on the WindowsDefenderATP enterprise app, POST each file,
then delete the app. The same pattern is documented in the top-level README's
Step 3 fallback block.
