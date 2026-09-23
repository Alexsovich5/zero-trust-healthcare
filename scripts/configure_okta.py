"""
Okta Identity Configuration

Automates Okta identity provider setup for healthcare
zero trust architecture.
"""

import logging
import requests

logger = logging.getLogger("okta_config")


class OktaConfigurator:
    def __init__(self, org_url: str, api_token: str):
        self.base_url = f"https://{org_url}/api/v1"
        self.headers = {
            "Authorization": f"SSWS {api_token}",
            "Content-Type": "application/json",
        }

    def create_healthcare_groups(self):
        groups = [
            {"name": "Healthcare-Clinicians", "description": "Clinical staff"},
            {"name": "Healthcare-Admin", "description": "Administrative staff"},
            {"name": "Healthcare-IT", "description": "IT operations team"},
            {"name": "Healthcare-MedDevices", "description": "Medical device service accounts"},
        ]
        for group in groups:
            resp = requests.post(f"{self.base_url}/groups", json={"profile": group}, headers=self.headers)
            logger.info("Created group %s: %d", group["name"], resp.status_code)

    def configure_mfa_policy(self):
        policy = {
            "name": "Healthcare MFA Policy",
            "type": "MFA_ENROLL",
            "status": "ACTIVE",
            "settings": {
                "factors": {
                    "okta_otp": {"enroll": {"self": "REQUIRED"}},
                    "okta_push": {"enroll": {"self": "OPTIONAL"}},
                }
            },
        }
        resp = requests.post(f"{self.base_url}/policies", json=policy, headers=self.headers)
        logger.info("MFA policy created: %d", resp.status_code)

    def configure_sign_on_policy(self):
        policy = {
            "name": "Healthcare Sign-On",
            "type": "OKTA_SIGN_ON",
            "status": "ACTIVE",
            "conditions": {"network": {"connection": "ANYWHERE"}},
        }
        resp = requests.post(f"{self.base_url}/policies", json=policy, headers=self.headers)
        logger.info("Sign-on policy: %d", resp.status_code)
