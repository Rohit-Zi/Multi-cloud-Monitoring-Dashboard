import { Severity, AlertStatus, CloudProvider } from "@/data/mockData";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";

export function SeverityBadge({ severity }: { severity: Severity }) {
  const styles: Record<Severity, string> = {
    critical: "bg-severity-critical/20 text-severity-critical border-severity-critical/30",
    high: "bg-severity-high/20 text-severity-high border-severity-high/30",
    medium: "bg-severity-medium/20 text-severity-medium border-severity-medium/30",
    low: "bg-severity-low/20 text-severity-low border-severity-low/30",
  };
  return (
    <Badge variant="outline" className={cn("text-[10px] font-bold uppercase", styles[severity])}>
      {severity}
    </Badge>
  );
}

export function StatusBadge({ status }: { status: AlertStatus }) {
  const styles: Record<AlertStatus, string> = {
    detected: "bg-severity-critical/10 text-severity-critical border-severity-critical/20",
    investigating: "bg-severity-medium/10 text-severity-medium border-severity-medium/20",
    resolved: "bg-primary/10 text-primary border-primary/20",
  };
  return (
    <Badge variant="outline" className={cn("text-[10px] capitalize", styles[status])}>
      {status}
    </Badge>
  );
}

export function CloudBadge({ cloud }: { cloud: CloudProvider }) {
  const styles: Record<CloudProvider, string> = {
    aws: "bg-aws/10 text-aws border-aws/20",
    azure: "bg-azure/10 text-azure border-azure/20",
    gcp: "bg-gcp/10 text-gcp border-gcp/20",
  };
  const labels: Record<CloudProvider, string> = { aws: "AWS", azure: "Azure", gcp: "GCP" };
  return (
    <Badge variant="outline" className={cn("text-[10px] font-semibold", styles[cloud])}>
      {labels[cloud]}
    </Badge>
  );
}

export function ResourceStatusDot({ status }: { status: string }) {
  const color: Record<string, string> = {
    running: "bg-primary",
    stopped: "bg-muted-foreground",
    warning: "bg-severity-medium",
    error: "bg-severity-critical",
  };
  return <span className={cn("inline-block h-2 w-2 rounded-full", color[status] || "bg-muted")} />;
}
