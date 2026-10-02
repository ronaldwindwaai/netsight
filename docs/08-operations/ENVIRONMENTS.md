# Environments

## Development
Synthetic/mock data only by default.

## Integration/Lab
Lab devices and test instances of LibreNMS/NetBox/Wazuh/etc.

## Staging
Production-like configuration, non-production credentials, controlled dataset.

## Production
Strict change control and protected secrets.

## DR
Documented recovery path and periodic restore test.

Never reuse production OAuth client secrets or network credentials in dev.
