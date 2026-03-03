"""
Severity Normalization Engine
Maps cloud-specific severity levels to unified scale: High, Medium, Low
"""

class SeverityNormalizer:
    
    # Severity mappings for each cloud provider
    SEVERITY_MAPS = {
        "aws": {
            "critical": "high",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "low"
        },
        "azure": {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "low"
        },
        "gcp": {
            "critical": "high",
            "high": "high",
            "medium": "medium",
            "low": "low"
        },
        "oci": {
            "critical": "high",
            "high": "high",
            "medium": "medium",
            "low": "low"
        },
        "cloudflare": {
            "high": "high",
            "medium": "medium",
            "low": "low"
        }
    }
    
    @staticmethod
    def normalize(provider: str, raw_severity: str) -> str:
        """
        Normalize severity from cloud-specific to unified scale
        
        Args:
            provider: Cloud provider (aws, azure, gcp, oci, cloudflare)
            raw_severity: Original severity from cloud provider
            
        Returns:
            Normalized severity (high, medium, low)
        """
        provider = provider.lower()
        raw_severity = raw_severity.lower()
        
        if provider not in SeverityNormalizer.SEVERITY_MAPS:
            return "medium"  # Default if provider unknown
        
        severity_map = SeverityNormalizer.SEVERITY_MAPS[provider]
        
        return severity_map.get(raw_severity, "medium")  # Default to medium if severity unknown