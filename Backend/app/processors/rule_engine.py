"""
Rule Engine - Evaluates cloud events against security rules
Decides which events become alerts and calculates severity
"""
from typing import Dict, Optional
from datetime import datetime, timedelta

class RuleEngine:
    
    # Define security rules for different event types
    SECURITY_RULES = {
        # AWS Rules
        "aws": {
            "root_account_login": {
                "severity": "critical",
                "alert": True,
                "title": "Root account login detected",
                "description": "AWS root account was used to sign in"
            },
            "resource_tag_update": {
            "severity": "low",
            "alert": True,
            "title": "Resource tag updated",
            "description": "Tags were updated on a cloud resource"
            },
            "unauthorized_api_call": {
                "severity": "high",
                "alert": True,
                "title": "Unauthorized API call",
                "description": "API call failed due to insufficient permissions"
            },
            "s3_bucket_public": {
                "severity": "critical",
                "alert": True,
                "title": "S3 bucket made public",
                "description": "S3 bucket permissions changed to public access"
            },
            "iam_policy_change": {
                "severity": "medium",
                "alert": True,
                "title": "IAM policy modified",
                "description": "IAM policy or role was modified"
            },
            "security_group_change": {
                "severity": "medium",
                "alert": True,
                "title": "Security group modified",
                "description": "EC2 security group rules were changed"
            },
            "failed_login": {
                "severity": "low",
                "alert": False,  # Only alert if multiple failures
                "title": "Failed console login",
                "description": "Console login attempt failed"
            },
            "iam_user_created_no_mfa": {
                "severity": "high",
                "alert": True,
                "title": "IAM user created without MFA",
                "description": "New IAM user created without multi-factor authentication"
            },
            "rds_snapshot_public": {
                "severity": "critical",
                "alert": True,
                "title": "Database snapshot made public",
                "description": "RDS database snapshot shared publicly"
            },
            "login_from_tor": {
                "severity": "high",
                "alert": True,
                "title": "Console login from TOR exit node",
                "description": "AWS console accessed through TOR network"
            },
            "iam_role_assumed": {
                "severity": "medium",
                "alert": True,
                "title": "Suspicious role assumption",
                "description": "IAM role assumed from unusual source"
            },
            "data_exfiltration": {
                "severity": "critical",
                "alert": True,
                "title": "Large data transfer to external account",
                "description": "Significant data transfer detected to external AWS account"
            },
            "unusual_download_volume": {
                "severity": "high",
                "alert": True,
                "title": "Unusual S3 download volume",
                "description": "Abnormal amount of data downloaded from S3"
            },
            "unencrypted_volume_created": {
                "severity": "medium",
                "alert": True,
                "title": "EBS volume created without encryption",
                "description": "New EBS volume created without encryption enabled"
            },
            "kms_key_deletion": {
                "severity": "high",
                "alert": True,
                "title": "KMS key scheduled for deletion",
                "description": "Encryption key scheduled for deletion"
            },
            "cloudtrail_disabled": {
                "severity": "critical",
                "alert": True,
                "title": "CloudTrail logging disabled",
                "description": "AWS CloudTrail audit logging has been disabled"
            },
            "guardduty_disabled": {
                "severity": "critical",
                "alert": True,
                "title": "GuardDuty detector disabled",
                "description": "AWS GuardDuty threat detection disabled"
            },
            "vpc_flow_logs_deleted": {
                "severity": "high",
                "alert": True,
                "title": "VPC Flow Logs deleted",
                "description": "VPC network flow logs have been deleted"
            },
            "port_scan_detected": {
                "severity": "high",
                "alert": True,
                "title": "Port scanning detected",
                "description": "Network port scanning activity detected on EC2 instance"
            },
            "brute_force_attack": {
                "severity": "high",
                "alert": True,
                "title": "Brute force SSH attack",
                "description": "Multiple failed SSH login attempts detected"
            },
            "crypto_mining": {
                "severity": "critical",
                "alert": True,
                "title": "Cryptocurrency mining detected",
                "description": "Cryptocurrency mining activity detected on EC2 instance"
            },
            "unusual_region_activity": {
                "severity": "medium",
                "alert": True,
                "title": "EC2 instance launched in unusual region",
                "description": "Instance launched in region not typically used"
            },
            "data_classification_violation": {
                "severity": "high",
                "alert": True,
                "title": "Production data copied to development",
                "description": "Data classification policy violation detected"
            },
            "mfa_disabled": {
                "severity": "high",
                "alert": True,
                "title": "Multi-factor authentication disabled",
                "description": "MFA removed from privileged account"
            },
            "unusual_country_access": {
                "severity": "medium",
                "alert": True,
                "title": "API calls from unusual country",
                "description": "API activity detected from unexpected geographic location"
            },
            "snapshot_shared_externally": {
                "severity": "high",
                "alert": True,
                "title": "Snapshot shared with unknown account",
                "description": "EBS snapshot shared with external AWS account"
            }
        },
        # Azure Rules
        "azure": {
            "admin_login": {
                "severity": "high",
                "alert": True,
                "title": "Administrator account login",
                "description": "Global administrator account was used"
            },
            "resource_deletion": {
                "severity": "high",
                "alert": True,
                "title": "Critical resource deleted",
                "description": "Resource group or critical resource was deleted"
            },
            "network_rule_change": {
                "severity": "medium",
                "alert": True,
                "title": "Network security rule modified",
                "description": "NSG rules were modified"
            }
        },
        
        # GCP Rules
        "gcp": {
            "service_account_key_created": {
                "severity": "high",
                "alert": True,
                "title": "Service account key created",
                "description": "New service account key was generated"
            },
            "firewall_rule_change": {
                "severity": "medium",
                "alert": True,
                "title": "Firewall rule modified",
                "description": "VPC firewall rule was changed"
            },
            "public_ip_assigned": {
                "severity": "low",
                "alert": True,
                "title": "Public IP assigned",
                "description": "Resource received a public IP address"
            }
        }
    }
    # Threshold-based rules (for pattern detection)
    THRESHOLD_RULES = {
        "failed_login_attempts": {
            "count": 2,
            "time_window_minutes": 10,
            "severity": "high",
            "title": "Multiple failed login attempts",
            "description": "Detected {count} failed login attempts in {time} minutes"
        },
        "api_call_spike": {
            "count": 100,
            "time_window_minutes": 5,
            "severity": "medium",
            "title": "Unusual API activity",
            "description": "Detected {count} API calls in {time} minutes"
        }
    }
    
    @staticmethod
    def evaluate_event(provider: str, event_type: str, event_data: Dict) -> Optional[Dict]:
        """
        Evaluate a cloud event against security rules
        
        Args:
            provider: Cloud provider (aws, azure, gcp)
            event_type: Type of event (e.g., 'root_account_login')
            event_data: Additional event context
            
        Returns:
            Dict with alert details if rule matches, None otherwise
        """
        provider = provider.lower()
        
        # Check if provider has rules
        if provider not in RuleEngine.SECURITY_RULES:
            return None
        
        # Check if event type matches a rule
        provider_rules = RuleEngine.SECURITY_RULES[provider]
        if event_type not in provider_rules:
            return None
        
        rule = provider_rules[event_type]
        
        # Check if this event should create an alert
        if not rule.get("alert", False):
            return None
        
        # Build alert data
        alert_data = {
            "provider": provider,
            "severity": rule["severity"],
            "title": rule["title"],
            "description": rule["description"],
            "event_type": event_type,
            "resource": event_data.get("resource", "Unknown"),
            "user": event_data.get("user", "Unknown"),
            "ip_address": event_data.get("ip_address", "Unknown"),
            "timestamp": event_data.get("timestamp", datetime.utcnow().isoformat())
        }
        
        return alert_data
    
    @staticmethod
    def evaluate_threshold(event_type: str, event_count: int, time_window_minutes: int) -> Optional[Dict]:
        """
        Evaluate threshold-based rules (e.g., multiple failed logins)
        
        Args:
            event_type: Type of threshold rule
            event_count: Number of events detected
            time_window_minutes: Time window for events
            
        Returns:
            Dict with alert details if threshold exceeded, None otherwise
        """
        if event_type not in RuleEngine.THRESHOLD_RULES:
            return None
        
        rule = RuleEngine.THRESHOLD_RULES[event_type]
        
        # Check if threshold exceeded
        if event_count < rule["count"]:
            return None
        
        # Build alert data
        alert_data = {
            "severity": rule["severity"],
            "title": rule["title"],
            "description": rule["description"].format(
                count=event_count,
                time=time_window_minutes
            )
        }
        
        return alert_data
    
    @staticmethod
    def add_custom_rule(provider: str, event_type: str, rule_config: Dict):
        """
        Add a custom rule at runtime
        
        Args:
            provider: Cloud provider
            event_type: Event type identifier
            rule_config: Rule configuration dict
        """
        if provider not in RuleEngine.SECURITY_RULES:
            RuleEngine.SECURITY_RULES[provider] = {}
        
        RuleEngine.SECURITY_RULES[provider][event_type] = rule_config