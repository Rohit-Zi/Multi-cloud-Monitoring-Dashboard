export type CloudProvider = "aws" | "azure" | "gcp";
export type Severity = "critical" | "high" | "medium" | "low";
export type AlertStatus = "detected" | "investigating" | "resolved";
export type AlertType =
  | "unauthorized_access"
  | "misconfiguration"
  | "data_exposure"
  | "malware"
  | "brute_force"
  | "policy_violation"
  | "anomaly";

export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  status: AlertStatus;
  type: AlertType;
  cloud: CloudProvider;
  resource: string;
  timestamp: string;
  recommendation: string;
}

export interface ActivityLog {
  id: string;
  action: string;
  user: string;
  cloud: CloudProvider;
  resource: string;
  timestamp: string;
  ip: string;
  status: "success" | "failure" | "warning";
  details: string;
}

export interface CloudStats {
  cloud: CloudProvider;
  totalAlerts: number;
  criticalAlerts: number;
  activeResources: number;
  complianceScore: number;
  threatScore: number;
  resolvedAlerts: number;
}

export interface Resource {
  id: string;
  name: string;
  type: "vm" | "database" | "storage" | "network" | "function" | "container";
  cloud: CloudProvider;
  status: "running" | "stopped" | "warning" | "error";
  region: string;
}

export interface ComplianceItem {
  framework: string;
  score: number;
  passed: number;
  failed: number;
  total: number;
  cloud: CloudProvider;
}

// ─── ALERTS ──────────────────────────────────────────
export const alerts: Alert[] = [
  { id: "ALT-001", title: "Root account login detected", description: "AWS root account was used to sign in from an unrecognized IP address.", severity: "critical", status: "detected", type: "unauthorized_access", cloud: "aws", resource: "IAM Root Account", timestamp: "2026-02-21T08:23:00Z", recommendation: "Enable MFA on root account and restrict usage." },
  { id: "ALT-002", title: "S3 bucket publicly accessible", description: "S3 bucket 'prod-logs-2026' has been configured with public read access.", severity: "critical", status: "investigating", type: "misconfiguration", cloud: "aws", resource: "s3://prod-logs-2026", timestamp: "2026-02-21T07:45:00Z", recommendation: "Remove public access and enable bucket policies." },
  { id: "ALT-003", title: "Brute force on Azure AD", description: "Multiple failed login attempts detected on Azure Active Directory.", severity: "high", status: "detected", type: "brute_force", cloud: "azure", resource: "Azure AD Tenant", timestamp: "2026-02-21T06:30:00Z", recommendation: "Enable conditional access policies and IP blocking." },
  { id: "ALT-004", title: "GCP service account key exposed", description: "Service account key found in public GitHub repository.", severity: "critical", status: "detected", type: "data_exposure", cloud: "gcp", resource: "sa-prod-api@project.iam", timestamp: "2026-02-21T05:12:00Z", recommendation: "Rotate the key immediately and audit access logs." },
  { id: "ALT-005", title: "Unusual data transfer volume", description: "Anomalous outbound data transfer of 500GB detected from EC2 instance.", severity: "high", status: "investigating", type: "anomaly", cloud: "aws", resource: "i-0abc123def456", timestamp: "2026-02-21T04:00:00Z", recommendation: "Investigate network flows and check for data exfiltration." },
  { id: "ALT-006", title: "NSG rule allows all inbound", description: "Network Security Group has a rule allowing all inbound traffic on all ports.", severity: "high", status: "detected", type: "misconfiguration", cloud: "azure", resource: "nsg-prod-web", timestamp: "2026-02-21T03:20:00Z", recommendation: "Restrict NSG rules to necessary ports and IPs only." },
  { id: "ALT-007", title: "Cloud SQL without SSL", description: "Cloud SQL instance is accepting connections without SSL encryption.", severity: "medium", status: "detected", type: "misconfiguration", cloud: "gcp", resource: "prod-db-main", timestamp: "2026-02-21T02:15:00Z", recommendation: "Enforce SSL connections on the Cloud SQL instance." },
  { id: "ALT-008", title: "Lambda function timeout spike", description: "Lambda function experiencing 95% timeout rate in last hour.", severity: "medium", status: "investigating", type: "anomaly", cloud: "aws", resource: "fn-process-orders", timestamp: "2026-02-20T23:45:00Z", recommendation: "Check function memory allocation and downstream dependencies." },
  { id: "ALT-009", title: "Suspicious API calls from new region", description: "API calls detected from a region not previously used by this account.", severity: "medium", status: "detected", type: "unauthorized_access", cloud: "azure", resource: "Azure Management API", timestamp: "2026-02-20T22:10:00Z", recommendation: "Verify the activity and restrict API access by region." },
  { id: "ALT-010", title: "Firewall rule too permissive", description: "GCP VPC firewall rule allows SSH from 0.0.0.0/0.", severity: "high", status: "detected", type: "misconfiguration", cloud: "gcp", resource: "vpc-prod-network", timestamp: "2026-02-20T21:00:00Z", recommendation: "Restrict SSH access to known IP ranges." },
  { id: "ALT-011", title: "Malware detected in container", description: "Container image scan found known malware signature.", severity: "critical", status: "detected", type: "malware", cloud: "aws", resource: "ecr://prod-api:latest", timestamp: "2026-02-20T19:30:00Z", recommendation: "Quarantine the container and rebuild from verified base image." },
  { id: "ALT-012", title: "Policy violation: unencrypted disk", description: "Azure managed disk created without encryption enabled.", severity: "low", status: "resolved", type: "policy_violation", cloud: "azure", resource: "disk-web-server-01", timestamp: "2026-02-20T18:00:00Z", recommendation: "Enable Azure Disk Encryption on all managed disks." },
  { id: "ALT-013", title: "Excessive IAM permissions", description: "GCP IAM role has overly broad permissions including owner access.", severity: "medium", status: "detected", type: "policy_violation", cloud: "gcp", resource: "roles/custom.admin", timestamp: "2026-02-20T16:45:00Z", recommendation: "Apply principle of least privilege to IAM roles." },
  { id: "ALT-014", title: "RDS instance publicly accessible", description: "RDS PostgreSQL instance has public accessibility enabled.", severity: "high", status: "detected", type: "misconfiguration", cloud: "aws", resource: "rds-prod-postgres", timestamp: "2026-02-20T15:20:00Z", recommendation: "Disable public access and use VPC endpoints." },
  { id: "ALT-015", title: "Azure Key Vault access anomaly", description: "Unusual pattern of secret reads from Key Vault detected.", severity: "medium", status: "investigating", type: "anomaly", cloud: "azure", resource: "kv-prod-secrets", timestamp: "2026-02-20T14:00:00Z", recommendation: "Review access policies and audit secret usage." },
];

// ─── ACTIVITY LOGS ───────────────────────────────────
export const activityLogs: ActivityLog[] = [
  { id: "LOG-001", action: "ConsoleLogin", user: "admin@corp.com", cloud: "aws", resource: "AWS Console", timestamp: "2026-02-21T08:23:00Z", ip: "203.0.113.42", status: "success", details: "Root account login from new IP address." },
  { id: "LOG-002", action: "PutBucketPolicy", user: "dev-team-sa", cloud: "aws", resource: "s3://prod-logs-2026", timestamp: "2026-02-21T07:44:00Z", ip: "10.0.1.50", status: "success", details: "Bucket policy changed to allow public read." },
  { id: "LOG-003", action: "SignInAttempt", user: "unknown@external.com", cloud: "azure", resource: "Azure AD", timestamp: "2026-02-21T06:30:00Z", ip: "198.51.100.23", status: "failure", details: "Failed login attempt - invalid credentials." },
  { id: "LOG-004", action: "CreateServiceAccountKey", user: "ci-pipeline@project.iam", cloud: "gcp", resource: "sa-prod-api", timestamp: "2026-02-21T05:10:00Z", ip: "172.16.0.100", status: "success", details: "New service account key created." },
  { id: "LOG-005", action: "AuthorizeSecurityGroupIngress", user: "ops-engineer", cloud: "aws", resource: "sg-0abc123", timestamp: "2026-02-21T04:30:00Z", ip: "10.0.2.25", status: "success", details: "Added inbound rule for port 22 from 0.0.0.0/0." },
  { id: "LOG-006", action: "ModifyNetworkSecurityGroup", user: "azure-admin@corp.com", cloud: "azure", resource: "nsg-prod-web", timestamp: "2026-02-21T03:19:00Z", ip: "10.1.0.15", status: "success", details: "NSG rule modified to allow all inbound traffic." },
  { id: "LOG-007", action: "UpdateFirewallRule", user: "gcp-admin@corp.com", cloud: "gcp", resource: "vpc-prod-network", timestamp: "2026-02-20T21:00:00Z", ip: "10.2.0.30", status: "warning", details: "Firewall rule updated - SSH open to all." },
  { id: "LOG-008", action: "DeleteBucketPolicy", user: "security-bot", cloud: "aws", resource: "s3://prod-logs-2026", timestamp: "2026-02-21T09:00:00Z", ip: "10.0.1.10", status: "success", details: "Public access policy removed by automated remediation." },
  { id: "LOG-009", action: "RotateServiceAccountKey", user: "security-admin@corp.com", cloud: "gcp", resource: "sa-prod-api", timestamp: "2026-02-21T09:15:00Z", ip: "10.2.0.5", status: "success", details: "Compromised service account key rotated." },
  { id: "LOG-010", action: "EnableMFA", user: "admin@corp.com", cloud: "aws", resource: "IAM Root Account", timestamp: "2026-02-21T09:30:00Z", ip: "203.0.113.42", status: "success", details: "MFA enabled on root account." },
  { id: "LOG-011", action: "CreateVirtualMachine", user: "dev@corp.com", cloud: "azure", resource: "vm-staging-01", timestamp: "2026-02-20T14:00:00Z", ip: "10.1.0.20", status: "success", details: "New VM created in staging environment." },
  { id: "LOG-012", action: "DeployFunction", user: "ci-pipeline@project.iam", cloud: "gcp", resource: "fn-data-processor", timestamp: "2026-02-20T12:00:00Z", ip: "172.16.0.100", status: "success", details: "Cloud Function deployed v2.3.1." },
  { id: "LOG-013", action: "StopInstance", user: "cost-optimizer", cloud: "aws", resource: "i-0def789ghi012", timestamp: "2026-02-20T10:00:00Z", ip: "10.0.3.5", status: "success", details: "Idle EC2 instance stopped for cost savings." },
  { id: "LOG-014", action: "SignInAttempt", user: "unknown@external.com", cloud: "azure", resource: "Azure AD", timestamp: "2026-02-21T06:31:00Z", ip: "198.51.100.23", status: "failure", details: "Failed login - account locked after 5 attempts." },
  { id: "LOG-015", action: "UpdateIAMPolicy", user: "security-admin@corp.com", cloud: "gcp", resource: "roles/custom.admin", timestamp: "2026-02-20T16:45:00Z", ip: "10.2.0.5", status: "success", details: "Removed owner permissions from custom admin role." },
];

// ─── RESOURCES ───────────────────────────────────────
export const resources: Resource[] = [
  { id: "RES-001", name: "prod-web-server-1", type: "vm", cloud: "aws", status: "running", region: "us-east-1" },
  { id: "RES-002", name: "prod-web-server-2", type: "vm", cloud: "aws", status: "running", region: "us-east-1" },
  { id: "RES-003", name: "rds-prod-postgres", type: "database", cloud: "aws", status: "warning", region: "us-east-1" },
  { id: "RES-004", name: "s3-prod-assets", type: "storage", cloud: "aws", status: "running", region: "us-east-1" },
  { id: "RES-005", name: "fn-process-orders", type: "function", cloud: "aws", status: "error", region: "us-east-1" },
  { id: "RES-006", name: "ecr-prod-api", type: "container", cloud: "aws", status: "error", region: "us-east-1" },
  { id: "RES-007", name: "vpc-prod", type: "network", cloud: "aws", status: "running", region: "us-east-1" },
  { id: "RES-008", name: "vm-prod-web-01", type: "vm", cloud: "azure", status: "running", region: "eastus" },
  { id: "RES-009", name: "vm-staging-01", type: "vm", cloud: "azure", status: "running", region: "eastus" },
  { id: "RES-010", name: "sql-prod-main", type: "database", cloud: "azure", status: "running", region: "eastus" },
  { id: "RES-011", name: "blob-prod-storage", type: "storage", cloud: "azure", status: "running", region: "eastus" },
  { id: "RES-012", name: "kv-prod-secrets", type: "storage", cloud: "azure", status: "warning", region: "eastus" },
  { id: "RES-013", name: "nsg-prod-web", type: "network", cloud: "azure", status: "error", region: "eastus" },
  { id: "RES-014", name: "gke-prod-cluster", type: "container", cloud: "gcp", status: "running", region: "us-central1" },
  { id: "RES-015", name: "prod-db-main", type: "database", cloud: "gcp", status: "warning", region: "us-central1" },
  { id: "RES-016", name: "gcs-prod-data", type: "storage", cloud: "gcp", status: "running", region: "us-central1" },
  { id: "RES-017", name: "fn-data-processor", type: "function", cloud: "gcp", status: "running", region: "us-central1" },
  { id: "RES-018", name: "vpc-prod-network", type: "network", cloud: "gcp", status: "error", region: "us-central1" },
];

// ─── COMPLIANCE ──────────────────────────────────────
export const complianceItems: ComplianceItem[] = [
  { framework: "CIS Benchmark", score: 78, passed: 156, failed: 44, total: 200, cloud: "aws" },
  { framework: "SOC 2", score: 85, passed: 170, failed: 30, total: 200, cloud: "aws" },
  { framework: "ISO 27001", score: 82, passed: 164, failed: 36, total: 200, cloud: "aws" },
  { framework: "PCI DSS", score: 71, passed: 142, failed: 58, total: 200, cloud: "aws" },
  { framework: "CIS Benchmark", score: 81, passed: 162, failed: 38, total: 200, cloud: "azure" },
  { framework: "SOC 2", score: 88, passed: 176, failed: 24, total: 200, cloud: "azure" },
  { framework: "ISO 27001", score: 79, passed: 158, failed: 42, total: 200, cloud: "azure" },
  { framework: "HIPAA", score: 90, passed: 180, failed: 20, total: 200, cloud: "azure" },
  { framework: "CIS Benchmark", score: 74, passed: 148, failed: 52, total: 200, cloud: "gcp" },
  { framework: "SOC 2", score: 82, passed: 164, failed: 36, total: 200, cloud: "gcp" },
  { framework: "ISO 27001", score: 77, passed: 154, failed: 46, total: 200, cloud: "gcp" },
  { framework: "NIST 800-53", score: 68, passed: 136, failed: 64, total: 200, cloud: "gcp" },
];

// ─── CLOUD STATS ─────────────────────────────────────
export const cloudStats: CloudStats[] = [
  { cloud: "aws", totalAlerts: 6, criticalAlerts: 3, activeResources: 7, complianceScore: 79, threatScore: 82, resolvedAlerts: 1 },
  { cloud: "azure", totalAlerts: 5, criticalAlerts: 0, activeResources: 6, complianceScore: 85, threatScore: 64, resolvedAlerts: 2 },
  { cloud: "gcp", totalAlerts: 4, criticalAlerts: 1, activeResources: 5, complianceScore: 75, threatScore: 71, resolvedAlerts: 1 },
];

// ─── CHART DATA ──────────────────────────────────────
export const alertsTrendData = [
  { date: "Feb 15", aws: 3, azure: 2, gcp: 1 },
  { date: "Feb 16", aws: 5, azure: 3, gcp: 2 },
  { date: "Feb 17", aws: 4, azure: 4, gcp: 3 },
  { date: "Feb 18", aws: 7, azure: 2, gcp: 4 },
  { date: "Feb 19", aws: 6, azure: 5, gcp: 2 },
  { date: "Feb 20", aws: 8, azure: 3, gcp: 5 },
  { date: "Feb 21", aws: 6, azure: 5, gcp: 4 },
];

export const threatCategoryData = [
  { category: "Misconfig", count: 5, fill: "hsl(var(--severity-high))" },
  { category: "Unauth Access", count: 3, fill: "hsl(var(--severity-critical))" },
  { category: "Data Exposure", count: 2, fill: "hsl(var(--severity-medium))" },
  { category: "Malware", count: 1, fill: "hsl(var(--severity-critical))" },
  { category: "Anomaly", count: 3, fill: "hsl(var(--primary))" },
  { category: "Policy Violation", count: 2, fill: "hsl(var(--severity-medium))" },
];

export const severityBreakdown = [
  { name: "Critical", value: 4, fill: "hsl(var(--severity-critical))" },
  { name: "High", value: 5, fill: "hsl(var(--severity-high))" },
  { name: "Medium", value: 4, fill: "hsl(var(--severity-medium))" },
  { name: "Low", value: 2, fill: "hsl(var(--severity-low))" },
];

export const cloudProviderInfo = {
  aws: { name: "Amazon Web Services", short: "AWS", color: "hsl(var(--aws))" },
  azure: { name: "Microsoft Azure", short: "Azure", color: "hsl(var(--azure))" },
  gcp: { name: "Google Cloud Platform", short: "GCP", color: "hsl(var(--gcp))" },
};

export function getCloudAlerts(cloud: CloudProvider) {
  return alerts.filter((a) => a.cloud === cloud);
}

export function getCloudLogs(cloud: CloudProvider) {
  return activityLogs.filter((l) => l.cloud === cloud);
}

export function getCloudResources(cloud: CloudProvider) {
  return resources.filter((r) => r.cloud === cloud);
}

export function getCloudCompliance(cloud: CloudProvider) {
  return complianceItems.filter((c) => c.cloud === cloud);
}

export function getCloudStats(cloud: CloudProvider) {
  return cloudStats.find((s) => s.cloud === cloud)!;
}
