import random

resources = [

# EC2
{"id": "i-83592d4f5e8b4103b", "type": "EC2", "name": "web-server-prod"},
{"id": "i-82c05480a6574b759", "type": "EC2", "name": "api-server-prod"},
{"id": "i-4f91126f5bc8454d9", "type": "EC2", "name": "worker-node"},

# S3
{"id": "prod-customer-database-backups", "type": "S3", "name": "prod-db-backups"},
{"id": "prod-application-logs", "type": "S3", "name": "app-logs"},
{"id": "data-analytics-exports", "type": "S3", "name": "analytics-data"},

# IAM
{"id": "ProductionAdminRole", "type": "IAM", "name": "ProductionAdminRole"},
{"id": "DevOpsAccessRole", "type": "IAM", "name": "DevOpsAccessRole"},

# Security Groups
{"id": "sg-7ec060e51cb3435bb", "type": "SecurityGroup", "name": "prod-web-sg"},
{"id": "sg-a3e51326c6a940f2a", "type": "SecurityGroup", "name": "db-access-sg"},

# RDS
{"id": "prod-postgres-db", "type": "RDS", "name": "customer-database"},
{"id": "analytics-db", "type": "RDS", "name": "analytics-db"},

# Lambda
{"id": "process-orders-lambda", "type": "Lambda", "name": "process-orders"},
{"id": "image-resize-lambda", "type": "Lambda", "name": "image-resizer"},

# EBS
{"id": "vol-84a1b33b9f0f5a1e", "type": "EBS", "name": "prod-storage-volume"},

# KMS
{"id": "kms-prod-key", "type": "KMS", "name": "prod-encryption-key"},

# VPC
{"id": "vpc-6e4d9c2b", "type": "VPC", "name": "production-vpc"},

# CloudTrail
{"id": "prod-audit-trail", "type": "CloudTrail", "name": "production-audit"}
]


def get_random_resource(resource_type=None):

    if resource_type:
        filtered = [r for r in resources if r["type"].lower() == resource_type.lower()]
        if filtered:
            return random.choice(filtered)

    return random.choice(resources)