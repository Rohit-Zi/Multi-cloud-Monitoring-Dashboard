"""
Multi-Cloud Log Generator
Generates realistic fake logs for AWS, Azure, GCP, OCI, Cloudflare
Each log is linked to an alert_id so users can view logs per alert
"""
import uuid
import json
import random
from datetime import datetime, timedelta
from typing import Dict, Optional


class LogGenerator:
    """
    Generates realistic cloud provider logs for simulated security events.
    Maps event_type → realistic log structure per cloud provider.
    """

    # -------------------------------------------------------------------------
    # AWS EVENT SOURCE MAPPING
    # Maps event_type to AWS service source
    # -------------------------------------------------------------------------
    AWS_EVENT_SOURCE_MAP = {
        "root_account_login":           "signin.amazonaws.com",
        "s3_bucket_public":             "s3.amazonaws.com",
        "iam_user_created_no_mfa":      "iam.amazonaws.com",
        "rds_snapshot_public":          "rds.amazonaws.com",
        "unauthorized_api_call":        "iam.amazonaws.com",
        "login_from_tor":               "signin.amazonaws.com",
        "security_group_change":        "ec2.amazonaws.com",
        "iam_policy_change":            "iam.amazonaws.com",
        "iam_role_assumed":             "sts.amazonaws.com",
        "data_exfiltration":            "s3.amazonaws.com",
        "unusual_download_volume":      "s3.amazonaws.com",
        "unencrypted_volume_created":   "ec2.amazonaws.com",
        "kms_key_deletion":             "kms.amazonaws.com",
        "cloudtrail_disabled":          "cloudtrail.amazonaws.com",
        "guardduty_disabled":           "guardduty.amazonaws.com",
        "vpc_flow_logs_deleted":        "ec2.amazonaws.com",
        "port_scan_detected":           "guardduty.amazonaws.com",
        "brute_force_attack":           "guardduty.amazonaws.com",
        "crypto_mining":                "guardduty.amazonaws.com",
        "unusual_region_activity":      "ec2.amazonaws.com",
        "data_classification_violation":"s3.amazonaws.com",
        "mfa_disabled":                 "iam.amazonaws.com",
        "unusual_country_access":       "signin.amazonaws.com",
        "snapshot_shared_externally":   "ec2.amazonaws.com",
        "console_login_success":        "signin.amazonaws.com",
        "ec2_instance_started":         "ec2.amazonaws.com",
        "iam_readonly_policy_attached": "iam.amazonaws.com",
        "s3_bucket_access":             "s3.amazonaws.com",
        "resource_tag_update":          "ec2.amazonaws.com",
    }

    # AWS event category mapping
    AWS_EVENT_CATEGORY_MAP = {
        "signin.amazonaws.com":         "Authentication",
        "iam.amazonaws.com":            "IAM",
        "s3.amazonaws.com":             "Data Access",
        "ec2.amazonaws.com":            "Infrastructure",
        "rds.amazonaws.com":            "Database",
        "kms.amazonaws.com":            "Encryption",
        "cloudtrail.amazonaws.com":     "Audit",
        "guardduty.amazonaws.com":      "Threat Detection",
        "sts.amazonaws.com":            "Authorization",
    }

    # -------------------------------------------------------------------------
    # AZURE EVENT OPERATION MAPPING
    # -------------------------------------------------------------------------
    AZURE_OPERATION_MAP = {
        "root_account_login":           "Microsoft.Authorization/elevateAccess/action",
        "unauthorized_api_call":        "Microsoft.Authorization/roleAssignments/write",
        "iam_policy_change":            "Microsoft.Authorization/policyAssignments/write",
        "security_group_change":        "Microsoft.Network/networkSecurityGroups/write",
        "data_exfiltration":            "Microsoft.Storage/storageAccounts/blobServices/read",
        "mfa_disabled":                 "Microsoft.AAD/users/authentication/write",
        "unusual_country_access":       "Microsoft.AAD/signIns/read",
        "login_from_tor":               "Microsoft.AAD/signIns/read",
        "cloudtrail_disabled":          "Microsoft.Insights/diagnosticSettings/delete",
        "crypto_mining":                "Microsoft.Compute/virtualMachines/write",
    }

    # -------------------------------------------------------------------------
    # GCP EVENT METHOD MAPPING
    # -------------------------------------------------------------------------
    GCP_METHOD_MAP = {
        "root_account_login":           "google.iam.admin.v1.SetIamPolicy",
        "unauthorized_api_call":        "google.iam.v1.IAMPolicy.GetIamPolicy",
        "iam_policy_change":            "google.iam.admin.v1.UpdateRole",
        "security_group_change":        "compute.firewalls.insert",
        "data_exfiltration":            "storage.objects.list",
        "cloudtrail_disabled":          "logging.sinks.delete",
        "crypto_mining":                "compute.instances.insert",
        "unusual_region_activity":      "compute.instances.insert",
        "mfa_disabled":                 "google.iam.admin.v1.UpdateUser",
    }

    # -------------------------------------------------------------------------
    # MAIN GENERATE METHOD
    # -------------------------------------------------------------------------
    @classmethod
    def generate_log(
        cls,
        alert_id: str,
        provider: str,
        event_type: str,
        event_data: Dict
    ) -> Dict:
        """
        Main entry point.
        Generates a log for the given provider and event type.
        Returns a dict ready to be saved as a Log model instance.
        """
        provider = provider.lower()

        if provider == "aws":
            raw = cls._generate_aws_log(event_type, event_data)
        elif provider == "azure":
            raw = cls._generate_azure_log(event_type, event_data)
        elif provider == "gcp":
            raw = cls._generate_gcp_log(event_type, event_data)
        elif provider == "oci":
            raw = cls._generate_oci_log(event_type, event_data)
        elif provider == "cloudflare":
            raw = cls._generate_cloudflare_log(event_type, event_data)
        else:
            raw = cls._generate_generic_log(event_type, event_data)

        # Return normalized log dict (maps to Log model fields)
        return {
            "log_id":         str(uuid.uuid4()),
            "alert_id":       alert_id,
            "cloud":          provider.upper(),
            "provider":       provider,
            "event_source":   raw.get("eventSource") or raw.get("operationName") or raw.get("methodName", "unknown"),
            "event_name":     event_type,
            "event_category": raw.get("eventCategory", "Security"),
            "user":           event_data.get("user", "Unknown"),
            "source_ip":      event_data.get("ip_address", "0.0.0.0"),
            "region":         event_data.get("region", "unknown"),
            "resource":       event_data.get("resource", "unknown"),
            "outcome":        raw.get("outcome", "Success"),
            "error_code":     event_data.get("error_code", None),
            "timestamp":      event_data.get("event_time", datetime.utcnow().isoformat()),
            "raw_log":        json.dumps(raw, indent=2)
        }

    # -------------------------------------------------------------------------
    # AWS LOG GENERATOR
    # -------------------------------------------------------------------------
    @classmethod
    def _generate_aws_log(cls, event_type: str, event_data: Dict) -> Dict:
        event_source = cls.AWS_EVENT_SOURCE_MAP.get(event_type, "aws.amazonaws.com")
        category = cls.AWS_EVENT_CATEGORY_MAP.get(event_source, "Management")

        return {
            "eventVersion":     "1.08",
            "eventTime":        event_data.get("event_time", datetime.utcnow().isoformat()),
            "eventSource":      event_source,
            "eventName":        event_type,
            "eventCategory":    category,
            "awsRegion":        event_data.get("region", "us-east-1"),
            "sourceIPAddress":  event_data.get("ip_address", "0.0.0.0"),
            "userAgent":        event_data.get("user_agent", "aws-cli/2.0"),
            "userIdentity": {
                "type":         "IAMUser" if event_data.get("user") != "root" else "Root",
                "principalId":  f"AIDA{uuid.uuid4().hex[:16].upper()}",
                "arn":          f"arn:aws:iam::123456789012:user/{event_data.get('user', 'unknown')}",
                "accountId":    "123456789012",
                "userName":     event_data.get("user", "unknown")
            },
            "requestParameters": {
                "resource":     event_data.get("resource", "N/A"),
            },
            "responseElements": {
                "requestId":    str(uuid.uuid4()),
                "status":       "Success"
            },
            "additionalEventData": {
                "mfaUsed":      event_data.get("mfa_used", False),
                "loginTo":      "https://console.aws.amazon.com/",
            },
            "eventID":          event_data.get("event_id", str(uuid.uuid4())),
            "readOnly":         False,
            "managementEvent":  True,
            "outcome":          "Success",
            "tlsDetails": {
                "tlsVersion":   "TLSv1.2",
                "cipherSuite":  "ECDHE-RSA-AES128-GCM-SHA256"
            }
        }

    # -------------------------------------------------------------------------
    # AZURE LOG GENERATOR
    # -------------------------------------------------------------------------
    @classmethod
    def _generate_azure_log(cls, event_type: str, event_data: Dict) -> Dict:
        operation = cls.AZURE_OPERATION_MAP.get(event_type, "Microsoft.Resources/deployments/write")

        return {
            "time":             event_data.get("event_time", datetime.utcnow().isoformat()),
            "resourceId":       f"/subscriptions/sub-{uuid.uuid4().hex[:8]}/resourceGroups/prod-rg/providers/{operation.rsplit('/', 1)[0]}",
            "operationName":    operation,
            "operationVersion": "1.0",
            "category":         "Administrative",
            "resultType":       "Success",
            "resultSignature":  "Succeeded",
            "durationMs":       random.randint(100, 2000),
            "callerIpAddress":  event_data.get("ip_address", "0.0.0.0"),
            "correlationId":    str(uuid.uuid4()),
            "eventSource":      operation,
            "outcome":          "Success",
            "identity": {
                "authorization": {
                    "action":   operation,
                    "scope":    "/subscriptions/sub-123456"
                },
                "claims": {
                    "name":         event_data.get("user", "unknown"),
                    "ipaddr":       event_data.get("ip_address", "0.0.0.0"),
                    "oid":          str(uuid.uuid4()),
                    "upn":          event_data.get("user", "unknown@company.com")
                }
            },
            "properties": {
                "statusCode":       "OK",
                "serviceRequestId": str(uuid.uuid4()),
                "resource":         event_data.get("resource", "N/A"),
                "region":           event_data.get("region", "eastus")
            }
        }

    # -------------------------------------------------------------------------
    # GCP LOG GENERATOR
    # -------------------------------------------------------------------------
    @classmethod
    def _generate_gcp_log(cls, event_type: str, event_data: Dict) -> Dict:
        method = cls.GCP_METHOD_MAP.get(event_type, "google.cloud.audit.AuditLog")

        return {
            "logName":          f"projects/my-project/logs/cloudaudit.googleapis.com%2Factivity",
            "timestamp":        event_data.get("event_time", datetime.utcnow().isoformat()),
            "severity":         "WARNING",
            "insertId":         str(uuid.uuid4()),
            "methodName":       method,
            "eventSource":      method,
            "outcome":          "Success",
            "resource": {
                "type":         "gce_instance",
                "labels": {
                    "project_id":   "my-project",
                    "zone":         event_data.get("region", "us-central1"),
                }
            },
            "protoPayload": {
                "@type":        "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {
                    "principalEmail": event_data.get("user", "unknown@project.iam.gserviceaccount.com")
                },
                "requestMetadata": {
                    "callerIp":         event_data.get("ip_address", "0.0.0.0"),
                    "callerSuppliedUserAgent": "google-cloud-sdk/400.0.0"
                },
                "serviceName":      method.split(".")[0] if "." in method else "cloudresourcemanager",
                "methodName":       method,
                "resourceName":     event_data.get("resource", "N/A"),
                "response": {
                    "@type":        "type.googleapis.com/google.protobuf.Empty"
                }
            }
        }

    # -------------------------------------------------------------------------
    # OCI LOG GENERATOR
    # -------------------------------------------------------------------------
    @classmethod
    def _generate_oci_log(cls, event_type: str, event_data: Dict) -> Dict:
        return {
            "logId":            str(uuid.uuid4()),
            "time":             event_data.get("event_time", datetime.utcnow().isoformat()),
            "type":             "com.oraclecloud.audit.logEvent",
            "source":           "oci-audit",
            "eventSource":      "oci-audit",
            "outcome":          "Success",
            "data": {
                "eventGroupingId":  str(uuid.uuid4()),
                "eventName":        event_type,
                "compartmentId":    f"ocid1.compartment.oc1..{uuid.uuid4().hex}",
                "compartmentName":  "production",
                "resourceName":     event_data.get("resource", "N/A"),
                "resourceId":       str(uuid.uuid4()),
                "identity": {
                    "principalName":    event_data.get("user", "unknown"),
                    "principalId":      str(uuid.uuid4()),
                    "authType":         "apikey",
                    "ipAddress":        event_data.get("ip_address", "0.0.0.0"),
                    "userAgent":        "Oracle-PythonSDK/2.0"
                },
                "request": {
                    "id":       str(uuid.uuid4()),
                    "action":   "POST",
                    "headers":  {},
                    "resource": event_data.get("resource", "N/A")
                },
                "response": {
                    "status":   "200",
                    "headers":  {},
                    "message":  "OK"
                }
            }
        }

    # -------------------------------------------------------------------------
    # CLOUDFLARE LOG GENERATOR
    # -------------------------------------------------------------------------
    @classmethod
    def _generate_cloudflare_log(cls, event_type: str, event_data: Dict) -> Dict:
        return {
            "RayID":            uuid.uuid4().hex[:16],
            "Timestamp":        event_data.get("event_time", datetime.utcnow().isoformat()),
            "ClientIP":         event_data.get("ip_address", "0.0.0.0"),
            "ClientRequestMethod": "POST",
            "ClientRequestURI": "/api/v4/zones",
            "EdgeResponseStatus": 200,
            "FirewallMatchesActions": ["log"],
            "FirewallMatchesRuleIDs": [f"rule-{uuid.uuid4().hex[:8]}"],
            "eventSource":      "cloudflare-audit",
            "outcome":          "Allowed",
            "ZoneName":         "company.com",
            "ActorEmail":       event_data.get("user", "unknown@company.com"),
            "ActorIP":          event_data.get("ip_address", "0.0.0.0"),
            "ActorType":        "user",
            "ID":               str(uuid.uuid4()),
            "Interface":        "API",
            "Metadata": {
                "resource":     event_data.get("resource", "N/A"),
                "event_type":   event_type
            },
            "NewValue":         {},
            "OldValue":         {},
            "OwnerID":          uuid.uuid4().hex,
            "ResourceID":       str(uuid.uuid4()),
            "ResourceType":     "zone"
        }

    # -------------------------------------------------------------------------
    # GENERIC FALLBACK LOG GENERATOR
    # -------------------------------------------------------------------------
    @classmethod
    def _generate_generic_log(cls, event_type: str, event_data: Dict) -> Dict:
        return {
            "logId":        str(uuid.uuid4()),
            "timestamp":    event_data.get("event_time", datetime.utcnow().isoformat()),
            "eventSource":  "generic-provider",
            "eventName":    event_type,
            "outcome":      "Success",
            "actor": {
                "user":     event_data.get("user", "unknown"),
                "ip":       event_data.get("ip_address", "0.0.0.0"),
            },
            "target": {
                "resource": event_data.get("resource", "N/A"),
                "region":   event_data.get("region", "unknown"),
            },
            "raw": event_data
        }