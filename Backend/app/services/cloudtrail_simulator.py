"""
AWS CloudTrail Event Simulator
Generates realistic security events across multiple AWS services
Simulates real-world attack patterns, misconfigurations, and compliance violations
"""
import random
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from app.services.resource_generator import get_random_resource

class CloudTrailSimulator:
    """
    Monster CloudTrail simulator with 25+ realistic security event scenarios
    """
    
    # Realistic IP addresses for different scenarios
    IP_POOLS = {
        "internal": ["10.0.1.50", "10.0.2.100", "172.16.0.25", "192.168.1.100"],
        "suspicious": ["185.220.101.42", "91.203.5.165", "45.142.120.50", "89.248.171.200"],
        "tor_exit": ["185.220.102.8", "23.129.64.200", "192.42.116.16"],
        "cloud_ips": ["54.239.28.85", "52.94.76.20", "18.208.0.10"]
    }
    
    # AWS regions
    REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "eu-central-1"]
    
    USERS = {
        "admins": ["admin@company.com", "root", "sysadmin@company.com", "cloudadmin@company.com"],
        "developers": ["dev1@company.com", "developer@company.com", "john.smith@company.com"],
        "suspicious": ["temp_user", "test123", "admin123", "backup_user"],
        "service_accounts": ["jenkins-sa", "terraform-deploy", "ci-cd-pipeline"]
    }
    
    # 25+ Realistic Security Event
    SECURITY_EVENTS = [
        # === CRITICAL THREATS ===
        {
            "name": "Root Account Login from Suspicious Location",
            "provider": "aws",
            "event_type": "root_account_login",
            "severity": "critical",
            "event_data": {
                "user": "root",
                "resource": "arn:aws:iam::123456789012:root",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["suspicious"]),
                "region": lambda: random.choice(CloudTrailSimulator.REGIONS),
                "user_agent": "AWS-Console/1.0",
                "mfa_used": False,
                "source_country": lambda: random.choice(["Russia", "China", "North Korea", "Iran"])
            }
        },
        {
            "name": "S3 Bucket Made Publicly Accessible",
            "provider": "aws",
            "event_type": "s3_bucket_public",
            "severity": "critical",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
                "resource": lambda: f"s3://prod-customer-data-{random.randint(1000, 9999)}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
                "region": lambda: random.choice(CloudTrailSimulator.REGIONS),
                "action": "PutBucketAcl",
                "bucket_contains": "PII, Financial Records, Customer Data"
            }
        },
        {
            "name": "IAM User Created Without MFA",
            "provider": "aws",
            "event_type": "iam_user_created_no_mfa",
            "severity": "high",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["admins"]),
                "resource": lambda: f"arn:aws:iam::123456789012:user/{random.choice(['contractor', 'temp-user', 'external-consultant'])}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
                "region": "us-east-1",
                "permissions_attached": "AdministratorAccess"
            }
        },
        {
            "name": "Database Snapshot Made Public",
            "provider": "aws",
            "event_type": "rds_snapshot_public",
            "severity": "critical",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
                "resource": lambda: f"arn:aws:rds:us-east-1:123456789012:snapshot:prod-db-snapshot-{random.randint(100, 999)}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
                "region": "us-east-1",
                "database_type": "PostgreSQL",
                "data_classification": "Confidential - Customer PII"
            }
        },
        {
    "name": "Successful Console Login",
    "provider": "aws",
    "event_type": "console_login_success",
    "severity": "low",
    "event_data": {
        "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
        "resource": "AWS Management Console",
        "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
        "region": "us-east-1",
        "mfa_used": True,
        "login_success": True
    }
},
        
        # === UNAUTHORIZED ACCESS ===
        {
            "name": "Unauthorized API Call - Access Denied",
            "provider": "aws",
            "event_type": "unauthorized_api_call",
            "severity": "high",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
                "resource": lambda: random.choice([
                    "ec2:TerminateInstances",
                    "s3:DeleteBucket",
                    "iam:DeleteUser",
                    "rds:DeleteDBInstance"
                ]),
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["suspicious"]),
                "region": lambda: random.choice(CloudTrailSimulator.REGIONS),
                "error_code": "AccessDenied",
                "attempts": lambda: random.randint(5, 20)
            }
        },
        {
            "name": "Console Login from TOR Exit Node",
            "provider": "aws",
            "event_type": "login_from_tor",
            "severity": "high",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
                "resource": "AWS Management Console",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["tor_exit"]),
                "region": "us-east-1",
                "mfa_used": False,
                "login_success": True
            }
        },
        {
    "name": "EC2 Instance Started",
    "provider": "aws",
    "event_type": "ec2_instance_started",
    "severity": "low",
    "event_data": {
        "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
        "resource": lambda: f"i-{uuid.uuid4().hex[:17]}",
        "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
        "region": lambda: random.choice(CloudTrailSimulator.REGIONS),
        "action": "StartInstances"
    }
},
        
        # === SECURITY GROUP VIOLATIONS ===
        {
            "name": "Security Group Opened to 0.0.0.0/0",
            "provider": "aws",
            "event_type": "security_group_change",
            "severity": "high",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
                "resource": lambda: f"sg-{uuid.uuid4().hex[:17]}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
                "region": lambda: random.choice(CloudTrailSimulator.REGIONS),
                "action": "AuthorizeSecurityGroupIngress",
                "port": lambda: random.choice([22, 3389, 1433, 3306, 5432, 27017]),
                "cidr": "0.0.0.0/0",
                "protocol": "TCP"
            }
        },
        {
            "name": "Security Group Rule Deleted During Production",
            "provider": "aws",
            "event_type": "security_group_change",
            "severity": "medium",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
                "resource": lambda: f"sg-{uuid.uuid4().hex[:17]}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
                "region": "us-east-1",
                "action": "RevokeSecurityGroupIngress",
                "affected_instances": lambda: random.randint(5, 50)
            }
        },
        {
    "name": "ReadOnly Policy Attached",
    "provider": "aws",
    "event_type": "iam_readonly_policy_attached",
    "severity": "low",
    "event_data": {
        "user": lambda: random.choice(CloudTrailSimulator.USERS["admins"]),
        "resource": lambda: f"arn:aws:iam::123456789012:user/{random.choice(['analyst', 'auditor'])}",
        "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
        "region": "us-east-1",
        "policy": "ReadOnlyAccess"
    }
},
        
        # === IAM POLICY CHANGES ===
        {
            "name": "IAM Policy Modified - Admin Access Granted",
            "provider": "aws",
            "event_type": "iam_policy_change",
            "severity": "high",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["admins"]),
                "resource": lambda: f"arn:aws:iam::123456789012:policy/{random.choice(['DeveloperPolicy', 'ReadOnlyAccess', 'SupportPolicy'])}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
                "region": "us-east-1",
                "action": "PutUserPolicy",
                "policy_change": "Added s3:*, ec2:*, iam:* permissions"
            }
        },
        {
            "name": "Suspicious Role Assumption",
            "provider": "aws",
            "event_type": "iam_role_assumed",
            "severity": "medium",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["suspicious"]),
                "resource": "arn:aws:iam::123456789012:role/ProductionAdminRole",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["suspicious"]),
                "region": lambda: random.choice(CloudTrailSimulator.REGIONS),
                "assumed_from": "Unknown External Account"
            }
        },
        {
    "name": "S3 Bucket Accessed",
    "provider": "aws",
    "event_type": "s3_bucket_access",
    "severity": "low",
    "event_data": {
        "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
        "resource": "s3://dev-application-logs",
        "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
        "region": "us-east-1",
        "action": "GetObject"
    }
},
        
        # === DATA EXFILTRATION PATTERNS ===
        {
            "name": "Large Data Transfer to External Account",
            "provider": "aws",
            "event_type": "data_exfiltration",
            "severity": "critical",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
                "resource": lambda: f"s3://prod-data-{random.randint(100, 999)}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["cloud_ips"]),
                "region": lambda: random.choice(CloudTrailSimulator.REGIONS),
                "action": "CopyObject",
                "data_size_gb": lambda: random.randint(50, 500),
                "destination": "External AWS Account: 987654321098"
            }
        },
        {
            "name": "Unusual S3 Download Volume",
            "provider": "aws",
            "event_type": "unusual_download_volume",
            "severity": "high",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
                "resource": "s3://prod-backup-archives",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["suspicious"]),
                "region": "us-east-1",
                "objects_downloaded": lambda: random.randint(1000, 10000),
                "data_size_gb": lambda: random.randint(100, 1000)
            }
        },
        
        # === ENCRYPTION & COMPLIANCE ===
        {
            "name": "EBS Volume Created Without Encryption",
            "provider": "aws",
            "event_type": "unencrypted_volume_created",
            "severity": "medium",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
                "resource": lambda: f"vol-{uuid.uuid4().hex[:17]}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
                "region": lambda: random.choice(CloudTrailSimulator.REGIONS),
                "volume_size_gb": lambda: random.randint(100, 1000),
                "attached_to": lambda: f"i-{uuid.uuid4().hex[:17]}"
            }
        },
        {
            "name": "KMS Key Scheduled for Deletion",
            "provider": "aws",
            "event_type": "kms_key_deletion",
            "severity": "high",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["admins"]),
                "resource": lambda: f"arn:aws:kms:us-east-1:123456789012:key/{uuid.uuid4()}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
                "region": "us-east-1",
                "deletion_date": (datetime.utcnow() + timedelta(days=30)).isoformat(),
                "encrypted_resources": lambda: random.randint(10, 100)
            }
        },
        
        # === CONFIGURATION CHANGES ===
        {
            "name": "CloudTrail Logging Disabled",
            "provider": "aws",
            "event_type": "cloudtrail_disabled",
            "severity": "critical",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["suspicious"]),
                "resource": "arn:aws:cloudtrail:us-east-1:123456789012:trail/prod-audit-trail",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["suspicious"]),
                "region": "us-east-1",
                "action": "StopLogging",
                "trail_captures": "All Management and Data Events"
            }
        },
        {
            "name": "GuardDuty Detector Disabled",
            "provider": "aws",
            "event_type": "guardduty_disabled",
            "severity": "critical",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["suspicious"]),
                "resource": lambda: f"arn:aws:guardduty:us-east-1:123456789012:detector/{uuid.uuid4().hex[:32]}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["suspicious"]),
                "region": "us-east-1",
                "action": "DeleteDetector"
            }
        },
        {
            "name": "VPC Flow Logs Deleted",
            "provider": "aws",
            "event_type": "vpc_flow_logs_deleted",
            "severity": "high",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
                "resource": lambda: f"fl-{uuid.uuid4().hex[:17]}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
                "region": lambda: random.choice(CloudTrailSimulator.REGIONS),
                "vpc_id": lambda: f"vpc-{uuid.uuid4().hex[:17]}"
            }
        },
        
        # === NETWORK ATTACKS ===
        {
            "name": "Port Scanning Detected",
            "provider": "aws",
            "event_type": "port_scan_detected",
            "severity": "high",
            "event_data": {
                "user": "SYSTEM",
                "resource": lambda: f"i-{uuid.uuid4().hex[:17]}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["suspicious"]),
                "region": lambda: random.choice(CloudTrailSimulator.REGIONS),
                "target_ports": "22, 80, 443, 3389, 8080, 8443",
                "scan_duration_seconds": lambda: random.randint(60, 300)
            }
        },
        {
            "name": "Brute Force SSH Attack",
            "provider": "aws",
            "event_type": "brute_force_attack",
            "severity": "high",
            "event_data": {
                "user": "SYSTEM",
                "resource": lambda: f"i-{uuid.uuid4().hex[:17]}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["suspicious"]),
                "region": lambda: random.choice(CloudTrailSimulator.REGIONS),
                "failed_attempts": lambda: random.randint(100, 500),
                "target_port": 22,
                "attack_duration_minutes": lambda: random.randint(10, 60)
            }
        },
        
        # === RESOURCE ABUSE ===
        {
            "name": "Cryptocurrency Mining Detected",
            "provider": "aws",
            "event_type": "crypto_mining",
            "severity": "critical",
            "event_data": {
                "user": "SYSTEM",
                "resource": lambda: f"i-{uuid.uuid4().hex[:17]}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["suspicious"]),
                "region": lambda: random.choice(CloudTrailSimulator.REGIONS),
                "cpu_usage_percent": lambda: random.randint(95, 100),
                "mining_pool": lambda: random.choice(["pool.minergate.com", "xmr-pool.com", "monero.crypto-pool.fr"]),
                "estimated_cost_per_hour": "$2.50"
            }
        },
        {
            "name": "EC2 Instance Launched in Unusual Region",
            "provider": "aws",
            "event_type": "unusual_region_activity",
            "severity": "medium",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
                "resource": lambda: f"i-{uuid.uuid4().hex[:17]}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
                "region": lambda: random.choice(["ap-east-1", "me-south-1", "af-south-1"]),
                "instance_type": lambda: random.choice(["p3.16xlarge", "p4d.24xlarge", "g4dn.16xlarge"]),
                "action": "RunInstances"
            }
        },
        
        # === COMPLIANCE VIOLATIONS ===
        {
            "name": "Production Data Copied to Development Account",
            "provider": "aws",
            "event_type": "data_classification_violation",
            "severity": "high",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
                "resource": "s3://prod-customer-database-backups",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
                "region": "us-east-1",
                "destination": "s3://dev-testing-bucket",
                "data_classification": "PII - GDPR Protected"
            }
        },
        {
            "name": "Multi-Factor Authentication Disabled",
            "provider": "aws",
            "event_type": "mfa_disabled",
            "severity": "high",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["admins"]),
                "resource": lambda: f"arn:aws:iam::123456789012:user/{random.choice(CloudTrailSimulator.USERS['admins'])}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
                "region": "us-east-1",
                "action": "DeactivateMFADevice",
                "user_has_admin_access": True
            }
        },
        
        # === UNUSUAL BEHAVIOR ===
        {
            "name": "API Calls from Unusual Country",
            "provider": "aws",
            "event_type": "unusual_country_access",
            "severity": "medium",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
                "resource": "AWS API",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["suspicious"]),
                "region": lambda: random.choice(CloudTrailSimulator.REGIONS),
                "source_country": lambda: random.choice(["Russia", "China", "Nigeria", "Brazil"]),
                "api_calls": lambda: random.randint(50, 200),
                "user_typical_country": "United States"
            }
        },
        {
            "name": "Snapshot Shared with Unknown Account",
            "provider": "aws",
            "event_type": "snapshot_shared_externally",
            "severity": "high",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
                "resource": lambda: f"snap-{uuid.uuid4().hex[:17]}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
                "region": "us-east-1",
                "shared_with_account": lambda: f"{random.randint(100000000000, 999999999999)}",
                "snapshot_size_gb": lambda: random.randint(100, 500)
            }
        },
        {
            "name": "Resource Tag Updated",
            "provider": "aws",
            "event_type": "resource_tag_update",
            "severity": "low",
            "event_data": {
                "user": lambda: random.choice(CloudTrailSimulator.USERS["developers"]),
                "resource": lambda: f"arn:aws:ec2:us-east-1:123456789012:instance/i-{uuid.uuid4().hex[:17]}",
                "ip_address": lambda: random.choice(CloudTrailSimulator.IP_POOLS["internal"]),
                "region": "us-east-1",
                "action": "CreateTags"
            }
        }
    ]
    
    def __init__(self, backend_url="http://127.0.0.1:8000"):
        self.backend_url = backend_url
        self.event_history = []
    
    def _resolve_dynamic_values(self, event_data: Dict) -> Dict:
        resolved = {}

        for key, value in event_data.items():
            if callable(value):
                resolved[key] = value()
            else:
                resolved[key] = value

    # Replace resource with one from resource generator
        resource = get_random_resource()
        resolved["resource"] = resource["name"]

        resolved["event_time"] = datetime.utcnow().isoformat()
        resolved["event_id"] = str(uuid.uuid4())

        return resolved
    
    def generate_random_event(self) -> Dict:
        """Generate a random security event"""
        template = random.choice(self.SECURITY_EVENTS).copy()
        event = {
            "provider": template["provider"],
            "event_type": template["event_type"],
            "event_data": self._resolve_dynamic_values(template["event_data"].copy())
        }
        self.event_history.append({
            "name": template["name"],
            "timestamp": datetime.utcnow().isoformat(),
            "event": event
        })
        return event
    
    def generate_specific_event(self, event_name: str) -> Optional[Dict]:
        """Generate a specific event by name"""
        template = next((e for e in self.SECURITY_EVENTS if e["name"] == event_name), None)
        if not template:
            return None
        
        event = {
            "provider": template["provider"],
            "event_type": template["event_type"],
            "event_data": self._resolve_dynamic_values(template["event_data"].copy())
        }
        return event
    
    def get_all_event_names(self) -> List[str]:
        """Get list of all available event scenarios"""
        return [event["name"] for event in self.SECURITY_EVENTS]
    
    def get_event_by_severity(self, severity: str) -> List[str]:
        """Get event names filtered by severity"""
        return [event["name"] for event in self.SECURITY_EVENTS if event.get("severity") == severity]