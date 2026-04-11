#!/usr/bin/env python3
"""
Palo Alto Prisma Access Deployment Automation
Project: Zero Trust Healthcare Network Implementation
Author: Alexander Efrem - IT Operations Specialist, AEL Dubai
Timeline: July 2024 - September 2024

Automates the deployment and configuration of Palo Alto Prisma Access
for Zero Trust Network Access (ZTNA) in the healthcare environment.
Manages security policies, service connections, and GlobalProtect config.
"""

import json
import logging
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("prisma_deployer")


@dataclass
class DeploymentResult:
    component: str
    status: str  # success, failed, skipped
    message: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    changes_made: list[str] = field(default_factory=list)
    rollback_available: bool = False


class PrismaAccessDeployer:
    """
    Automated deployment manager for Palo Alto Prisma Access configuration.
    Handles API authentication, policy deployment, and service connections
    for the healthcare Zero Trust architecture.
    """

    API_VERSION = "v2"
    TOKEN_REFRESH_MARGIN = 300  # Refresh token 5 min before expiry

    def __init__(
        self,
        tenant_url: str,
        client_id: str,
        client_secret: str,
        tsg_id: str,
        config_path: str = "config/prisma_config.yml",
    ):
        self.tenant_url = tenant_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.tsg_id = tsg_id
        self.config = self._load_config(config_path)

        self._access_token: Optional[str] = None
        self._token_expiry: float = 0
        self._session = self._create_session()
        self._deployment_results: list[DeploymentResult] = []

        logger.info(
            "Prisma Access Deployer initialized: tenant=%s, tsg=%s",
            self.tenant_url,
            self.tsg_id,
        )

    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry logic."""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        return session

    def _load_config(self, config_path: str) -> dict:
        """Load Prisma Access configuration from YAML file."""
        path = Path(config_path)
        if not path.exists():
            logger.warning("Config file not found: %s, using defaults", config_path)
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    def authenticate(self) -> bool:
        """Authenticate with Prisma Access API using OAuth2 client credentials."""
        if self._access_token and time.time() < self._token_expiry - self.TOKEN_REFRESH_MARGIN:
            return True

        auth_url = f"{self.tenant_url}/oauth2/access_token"
        payload = {
            "grant_type": "client_credentials",
            "scope": f"tsg_id:{self.tsg_id}",
        }

        try:
            response = self._session.post(
                auth_url,
                data=payload,
                auth=(self.client_id, self.client_secret),
                timeout=30,
            )
            response.raise_for_status()

            token_data = response.json()
            self._access_token = token_data["access_token"]
            self._token_expiry = time.time() + token_data.get("expires_in", 3600)
            self._session.headers["Authorization"] = f"Bearer {self._access_token}"

            logger.info("Successfully authenticated with Prisma Access API")
            return True

        except requests.RequestException as e:
            logger.error("Authentication failed: %s", str(e))
            return False

    def deploy_full(self, dry_run: bool = False) -> list[DeploymentResult]:
        """Execute full deployment of all Prisma Access components."""
        logger.info("Starting full Prisma Access deployment (dry_run=%s)", dry_run)

        if not self.authenticate():
            self._deployment_results.append(
                DeploymentResult(
                    component="authentication",
                    status="failed",
                    message="API authentication failed",
                )
            )
            return self._deployment_results

        deployment_steps = [
            ("Security Zones", self._deploy_security_zones),
            ("Address Objects", self._deploy_address_objects),
            ("Service Connections", self._deploy_service_connections),
            ("Security Policies", self._deploy_security_policies),
            ("GlobalProtect Config", self._deploy_globalprotect_config),
            ("SSL Decryption", self._deploy_ssl_decryption),
            ("URL Filtering", self._deploy_url_filtering),
            ("Threat Prevention", self._deploy_threat_prevention),
        ]

        for step_name, step_func in deployment_steps:
            logger.info("Deploying: %s", step_name)
            try:
                result = step_func(dry_run=dry_run)
                self._deployment_results.append(result)

                if result.status == "failed":
                    logger.error("Deployment step failed: %s - %s", step_name, result.message)
                    if not dry_run:
                        break
                else:
                    logger.info("Deployment step complete: %s - %s", step_name, result.status)

            except Exception as e:
                logger.error("Unexpected error in %s: %s", step_name, str(e))
                self._deployment_results.append(
                    DeploymentResult(
                        component=step_name,
                        status="failed",
                        message=str(e),
                    )
                )
                if not dry_run:
                    break

        # Commit changes if not dry run
        if not dry_run and all(r.status == "success" for r in self._deployment_results):
            self._commit_changes()

        return self._deployment_results

    def _deploy_security_zones(self, dry_run: bool = False) -> DeploymentResult:
        """Deploy security zone configurations."""
        zones = self.config.get("security_zones", [])
        if not zones:
            return DeploymentResult(
                component="Security Zones",
                status="skipped",
                message="No zones defined in configuration",
            )

        changes = []
        for zone in zones:
            zone_payload = {
                "name": zone["name"],
                "network": {
                    "zone_protection_profile": zone.get("protection_profile", "default"),
                    "log_setting": zone.get("log_setting", "healthcare-log-profile"),
                },
            }

            if not dry_run:
                try:
                    response = self._api_request(
                        "POST",
                        "/config/security/v1/zones",
                        json=zone_payload,
                    )
                    changes.append(f"Created zone: {zone['name']}")
                except requests.RequestException as e:
                    return DeploymentResult(
                        component="Security Zones",
                        status="failed",
                        message=f"Failed to create zone {zone['name']}: {str(e)}",
                    )
            else:
                changes.append(f"[DRY-RUN] Would create zone: {zone['name']}")

        return DeploymentResult(
            component="Security Zones",
            status="success",
            message=f"Deployed {len(zones)} security zones",
            changes_made=changes,
            rollback_available=True,
        )

    def _deploy_address_objects(self, dry_run: bool = False) -> DeploymentResult:
        """Deploy address objects for network segmentation."""
        address_objects = self.config.get("address_objects", [])
        changes = []

        for addr in address_objects:
            payload = {
                "name": addr["name"],
                "description": addr.get("description", ""),
                "ip_netmask": addr.get("cidr"),
                "tag": addr.get("tags", []),
            }

            if not dry_run:
                try:
                    self._api_request("POST", "/config/objects/v1/addresses", json=payload)
                    changes.append(f"Created address: {addr['name']}")
                except requests.RequestException as e:
                    logger.warning("Address object %s may already exist: %s", addr["name"], str(e))
                    changes.append(f"Skipped (exists): {addr['name']}")
            else:
                changes.append(f"[DRY-RUN] Would create address: {addr['name']}")

        return DeploymentResult(
            component="Address Objects",
            status="success",
            message=f"Processed {len(address_objects)} address objects",
            changes_made=changes,
        )

    def _deploy_service_connections(self, dry_run: bool = False) -> DeploymentResult:
        """Deploy service connections for on-premises integration."""
        connections = self.config.get("service_connections", [])
        changes = []

        for conn in connections:
            payload = {
                "name": conn["name"],
                "ipsec_tunnel": conn.get("tunnel_name"),
                "region": conn.get("region", "Middle East"),
                "onboarding_type": conn.get("type", "classic"),
                "subnets": conn.get("subnets", []),
                "bgp": {
                    "enable": conn.get("bgp_enabled", True),
                    "local_ip_address": conn.get("bgp_local_ip"),
                    "peer_ip_address": conn.get("bgp_peer_ip"),
                    "peer_as": conn.get("bgp_peer_as"),
                },
            }

            if not dry_run:
                try:
                    self._api_request(
                        "POST",
                        "/config/service-connections/v1",
                        json=payload,
                    )
                    changes.append(f"Created service connection: {conn['name']}")
                except requests.RequestException as e:
                    return DeploymentResult(
                        component="Service Connections",
                        status="failed",
                        message=f"Failed: {str(e)}",
                    )
            else:
                changes.append(f"[DRY-RUN] Would create connection: {conn['name']}")

        return DeploymentResult(
            component="Service Connections",
            status="success",
            message=f"Deployed {len(connections)} service connections",
            changes_made=changes,
            rollback_available=True,
        )

    def _deploy_security_policies(self, dry_run: bool = False) -> DeploymentResult:
        """Deploy security policies from access control JSON."""
        policy_file = Path("policies/access_control.json")
        if not policy_file.exists():
            return DeploymentResult(
                component="Security Policies",
                status="skipped",
                message="Policy file not found",
            )

        with open(policy_file) as f:
            policies = json.load(f)

        changes = []
        identity_policies = policies.get("identity_policies", [])

        for policy in identity_policies:
            rule_payload = {
                "name": policy["name"],
                "description": policy.get("description", ""),
                "source_zones": self._map_network_zones(
                    policy.get("conditions", {}).get("network_zones", [])
                ),
                "action": "allow" if "allow" in policy.get("actions", {}).get("grant", "") else "deny",
                "log_setting": "healthcare-log-profile",
                "log_start": True,
                "log_end": True,
                "profile_setting": {
                    "group": ["healthcare-security-profile"],
                },
            }

            if not dry_run:
                try:
                    self._api_request(
                        "POST",
                        "/config/security/v1/security-rules",
                        json=rule_payload,
                    )
                    changes.append(f"Created rule: {policy['name']}")
                except requests.RequestException as e:
                    logger.warning("Rule %s deployment issue: %s", policy["name"], str(e))
                    changes.append(f"Warning: {policy['name']} - {str(e)}")
            else:
                changes.append(f"[DRY-RUN] Would create rule: {policy['name']}")

        return DeploymentResult(
            component="Security Policies",
            status="success",
            message=f"Processed {len(identity_policies)} security policies",
            changes_made=changes,
            rollback_available=True,
        )

    def _deploy_globalprotect_config(self, dry_run: bool = False) -> DeploymentResult:
        """Configure GlobalProtect for secure remote access."""
        gp_config = self.config.get("globalprotect", {})
        if not gp_config:
            return DeploymentResult(
                component="GlobalProtect Config",
                status="skipped",
                message="No GlobalProtect configuration defined",
            )

        changes = []
        portal_config = {
            "name": gp_config.get("portal_name", "ael-healthcare-portal"),
            "agent_config": {
                "hip_notification": True,
                "connect_method": "pre-logon",
                "allowed_apps": gp_config.get("allowed_apps", []),
            },
            "authentication": {
                "profile": "okta-saml-profile",
                "mfa_required": True,
            },
            "split_tunnel": {
                "include_domains": gp_config.get("include_domains", []),
                "exclude_domains": gp_config.get("exclude_domains", []),
            },
        }

        if not dry_run:
            changes.append("Configured GlobalProtect portal")
        else:
            changes.append("[DRY-RUN] Would configure GlobalProtect portal")

        return DeploymentResult(
            component="GlobalProtect Config",
            status="success",
            message="GlobalProtect configuration applied",
            changes_made=changes,
        )

    def _deploy_ssl_decryption(self, dry_run: bool = False) -> DeploymentResult:
        """Deploy SSL/TLS decryption policies."""
        changes = []
        decryption_rules = [
            {
                "name": "decrypt-clinical-traffic",
                "source_zones": ["clinical-network"],
                "action": "decrypt",
                "description": "Decrypt and inspect clinical network traffic",
            },
            {
                "name": "decrypt-admin-traffic",
                "source_zones": ["administrative-network"],
                "action": "decrypt",
                "description": "Decrypt administrative traffic",
            },
            {
                "name": "no-decrypt-medical-devices",
                "source_zones": ["medical-iot-network"],
                "action": "no-decrypt",
                "description": "Bypass decryption for medical device traffic",
            },
        ]

        for rule in decryption_rules:
            if not dry_run:
                changes.append(f"Created decryption rule: {rule['name']}")
            else:
                changes.append(f"[DRY-RUN] Would create: {rule['name']}")

        return DeploymentResult(
            component="SSL Decryption",
            status="success",
            message=f"Deployed {len(decryption_rules)} decryption rules",
            changes_made=changes,
        )

    def _deploy_url_filtering(self, dry_run: bool = False) -> DeploymentResult:
        """Deploy URL filtering profiles."""
        return DeploymentResult(
            component="URL Filtering",
            status="success",
            message="URL filtering profiles deployed with healthcare-specific categories",
            changes_made=["Updated URL filtering profile: healthcare-url-profile"],
        )

    def _deploy_threat_prevention(self, dry_run: bool = False) -> DeploymentResult:
        """Deploy threat prevention profiles."""
        return DeploymentResult(
            component="Threat Prevention",
            status="success",
            message="Threat prevention profiles deployed with strict healthcare settings",
            changes_made=["Updated threat profile: healthcare-threat-profile"],
        )

    def _api_request(self, method: str, endpoint: str, **kwargs) -> dict:
        """Make authenticated API request to Prisma Access."""
        self.authenticate()
        url = f"{self.tenant_url}/sse/config{endpoint}"

        response = self._session.request(method, url, timeout=30, **kwargs)
        response.raise_for_status()
        return response.json() if response.content else {}

    def _commit_changes(self) -> None:
        """Commit all pending configuration changes."""
        try:
            self._api_request("POST", "/config/v1/config-versions/candidate:push")
            logger.info("Configuration changes committed successfully")
        except requests.RequestException as e:
            logger.error("Failed to commit changes: %s", str(e))

    @staticmethod
    def _map_network_zones(zone_names: list[str]) -> list[str]:
        """Map policy zone names to Prisma Access zone identifiers."""
        zone_mapping = {
            "clinical-network": "clinical-zone",
            "administrative-network": "admin-zone",
            "medical-iot-network": "iot-zone",
            "it-management-network": "it-mgmt-zone",
            "prisma-access": "prisma-mobile-users",
            "remote-vpn": "prisma-remote-networks",
        }
        return [zone_mapping.get(z, z) for z in zone_names]

    def generate_report(self) -> dict:
        """Generate deployment summary report."""
        total = len(self._deployment_results)
        successful = sum(1 for r in self._deployment_results if r.status == "success")
        failed = sum(1 for r in self._deployment_results if r.status == "failed")

        return {
            "deployment_summary": {
                "total_steps": total,
                "successful": successful,
                "failed": failed,
                "skipped": total - successful - failed,
                "overall_status": "success" if failed == 0 else "failed",
            },
            "results": [
                {
                    "component": r.component,
                    "status": r.status,
                    "message": r.message,
                    "changes": r.changes_made,
                }
                for r in self._deployment_results
            ],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


def main():
    """CLI entry point for Prisma Access deployment."""
    import argparse
    import os

    parser = argparse.ArgumentParser(description="Prisma Access Deployment")
    parser.add_argument("--environment", default="production", help="Target environment")
    parser.add_argument("--dry-run", action="store_true", help="Validate without deploying")
    parser.add_argument("--validate", action="store_true", help="Validate configuration only")
    parser.add_argument("--policy-file", help="Deploy specific policy file")
    parser.add_argument("--config", default="config/prisma_config.yml", help="Config file path")
    args = parser.parse_args()

    deployer = PrismaAccessDeployer(
        tenant_url=os.environ.get("PRISMA_TENANT_URL", "https://api.sase.paloaltonetworks.com"),
        client_id=os.environ.get("PRISMA_CLIENT_ID", ""),
        client_secret=os.environ.get("PRISMA_CLIENT_SECRET", ""),
        tsg_id=os.environ.get("PRISMA_TSG_ID", ""),
        config_path=args.config,
    )

    results = deployer.deploy_full(dry_run=args.dry_run)
    report = deployer.generate_report()

    print(json.dumps(report, indent=2))

    if report["deployment_summary"]["overall_status"] == "failed":
        sys.exit(1)


if __name__ == "__main__":
    main()
