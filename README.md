# Zero Trust Healthcare Network Implementation

Zero Trust network implementation for healthcare environment using Palo Alto Prisma for network security, Okta for identity management, and Microsoft Sentinel for SIEM and threat detection.

Personal project, built to explore how zero-trust access policy is expressed as code across Okta, Prisma Access and Sentinel. It is not production software — see **Status** below for exactly what is and isn't implemented.

## Status

**Implemented**

- Okta and Prisma Access configuration scripts
- Network segmentation and access-control policy documents (JSON)
- KQL detection queries for Microsoft Sentinel
- An incident-response playbook (Ansible)

**Not implemented / known limitations**

- Configuration-and-policy only — there is no running application
- Scripts have never been executed against live tenants
- No tests; no CI validation of the policy JSON

## Built with

- **Python** — requests, PyYAML, azure-identity, azure-monitor-query

## Running it

```bash
pip install -r requirements.txt
```

## Layout

```
config/
  okta_config.yml
  prisma_config.yml
monitoring/
  sentinel_queries.kql
playbooks/
  incident_response.yml
policies/
  access_control.json
  network_segmentation.json
requirements.txt
scripts/
  configure_okta.py
  deploy_prisma.py
  sentinel_rules.py
```

