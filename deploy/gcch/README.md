# Azure Government / GCC High

This folder contains Azure Government / GCC High variants of the UAL TimeBomb templates. They use government-cloud defaults for ARM, Defender for Endpoint, and Microsoft Security Advanced Hunting endpoints.

Values to review before deploying:

```text
DefenderApiBaseUri
DefenderApiAudience
AdvancedHuntingApiBaseUri
AdvancedHuntingApiAudience
ArmBaseUri
ArmAudience
```

Validate endpoint values with the tenant's Microsoft Defender and Azure cloud documentation before deploying, especially if the tenant is GCC rather than GCC High.
