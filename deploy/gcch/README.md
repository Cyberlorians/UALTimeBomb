# Azure Government / GCC High

The commercial templates are parameterized for API base URIs and managed identity audiences. For Azure Government or GCC High deployments, copy the commercial template and override the endpoint parameters for the target cloud.

Common values to review:

```text
DefenderApiBaseUri
DefenderApiAudience
AdvancedHuntingApiBaseUri
AdvancedHuntingApiAudience
ArmBaseUri
ArmAudience
```

Validate endpoint values with the tenant's Microsoft Defender and Azure cloud documentation before deploying.
