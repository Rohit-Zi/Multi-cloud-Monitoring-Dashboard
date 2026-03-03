import { useState, useMemo } from "react";
import { SeverityBadge, StatusBadge, CloudBadge } from "@/components/dashboard/Badges";
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Bell, ShieldAlert, CheckCircle, Search } from "lucide-react";
import type { Alert } from "@/data/mockData";
import { useEffect,} from "react";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [cloudFilter, setCloudFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [search, setSearch] = useState("");

  const sanitizeSearch = (value: string) => {
    return value.replace(/[<>"'&]/g, "").slice(0, 100);
  };
  const [selectedAlert, setSelectedAlert] = useState<any | null>(null);

  const filtered = useMemo(() => {
    return alerts.filter((a) => {
      if (cloudFilter !== "all" && a.cloud !== cloudFilter) return false;
      if (severityFilter !== "all" && a.severity !== severityFilter) return false;
      if (statusFilter !== "all" && a.status !== statusFilter) return false;
      if (search && !a.title.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [alerts, cloudFilter, severityFilter, statusFilter, search]);

  const openCount = alerts.filter((a) => a.status === "detected").length;
  const criticalCount = alerts.filter((a) => a.severity === "high").length;
  const resolvedCount = alerts.filter((a) => a.status === "resolved").length;

useEffect(() => {
  fetch("http://127.0.0.1:8000/alerts")
    .then(res => res.json())
    .then(data => {
      const normalized = data.map((a: Alert) => ({
        ...a,
        cloud: a.cloud.toLowerCase(),
      }));
      setAlerts(normalized); 
    })
    .catch(err => console.error(err));
}, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Security Alerts</h1>
        <p className="text-sm text-muted-foreground mt-1">Monitor and manage security alerts across all cloud providers</p>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: "Open Alerts", value: openCount, icon: Bell, color: "text-severity-high" },
          { label: "Critical", value: criticalCount, icon: ShieldAlert, color: "text-severity-critical" },
          { label: "Resolved", value: resolvedCount, icon: CheckCircle, color: "text-primary" },
        ].map((s) => (
          <div key={s.label} className="glass-card p-4 flex items-center gap-3">
            <s.icon className={`h-5 w-5 ${s.color}`} />
            <div>
              <p className="text-xl font-bold">{s.value}</p>
              <p className="text-[11px] text-muted-foreground">{s.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="glass-card p-4 flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            value={search}
            onChange={(e) => setSearch(sanitizeSearch(e.target.value))}
            placeholder="Search alerts..."
            className="w-full bg-secondary/50 rounded-lg pl-9 pr-3 py-2 text-sm text-foreground placeholder:text-muted-foreground outline-none border border-border/50 focus:border-primary/50"
          />
        </div>
        <Select value={cloudFilter} onValueChange={setCloudFilter}>
          <SelectTrigger className="w-[120px] bg-secondary/50 border-border/50"><SelectValue placeholder="Cloud" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Clouds</SelectItem>
            <SelectItem value="aws">AWS</SelectItem>
            <SelectItem value="azure">Azure</SelectItem>
            <SelectItem value="gcp">GCP</SelectItem>
          </SelectContent>
        </Select>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-[120px] bg-secondary/50 border-border/50"><SelectValue placeholder="Severity" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-[120px] bg-secondary/50 border-border/50"><SelectValue placeholder="Status" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All</SelectItem>
            <SelectItem value="detected">Detected</SelectItem>
            <SelectItem value="investigating">Investigating</SelectItem>
            <SelectItem value="resolved">Resolved</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <div className="glass-card overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="border-border/30 hover:bg-transparent">
              <TableHead className="text-muted-foreground">Alert</TableHead>
              <TableHead className="text-muted-foreground">Severity {severityFilter !== "all" && `(${filtered.length})`}</TableHead>
              <TableHead className="text-muted-foreground">Status {statusFilter !== "all" && `(${filtered.length})`}</TableHead>
              <TableHead className="text-muted-foreground">Cloud</TableHead>
              <TableHead className="text-muted-foreground">Resource</TableHead>
              <TableHead className="text-muted-foreground">Time</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map((alert) => (
              <TableRow
                key={alert.id}
                className="border-border/20 cursor-pointer hover:bg-secondary/30"
                onClick={() => setSelectedAlert(alert)}
              >
                <TableCell>
                  <p className="font-medium text-sm">{alert.title}</p>
                  <p className="text-[10px] text-muted-foreground">ALT-{alert.id.slice(0, 6).toUpperCase()}</p>
                </TableCell>
                <TableCell><SeverityBadge severity={alert.severity} /></TableCell>
                <TableCell><StatusBadge status={alert.status} /></TableCell>
                <TableCell><CloudBadge cloud={alert.cloud} /></TableCell>
                <TableCell className="text-xs text-muted-foreground font-mono">{alert.resource}</TableCell>
                <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                  {new Date(alert.created_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {filtered.length === 0 && (
          <div className="flex items-center justify-center py-12 text-muted-foreground text-sm">No alerts found</div>
        )}
      </div>

      {/* Alert Detail Dialog */}
      <Dialog open={!!selectedAlert} onOpenChange={() => setSelectedAlert(null)}>
        <DialogContent className="glass-card border-border/50 max-w-lg">
          {selectedAlert && (
            <>
              <DialogHeader>
                <DialogTitle className="text-lg">{selectedAlert.title}</DialogTitle>
              </DialogHeader>
              <div className="space-y-4 text-sm">
                <div className="flex gap-2">
                  <SeverityBadge severity={selectedAlert.severity} />
                  <StatusBadge status={selectedAlert.status} />
                  <CloudBadge cloud={selectedAlert.cloud} />
                </div>
                <div>
                  <p className="text-muted-foreground text-xs mb-1">Description</p>
                  <p>{selectedAlert.description}</p>
                </div>
                <div>
                  <p className="text-muted-foreground text-xs mb-1">Affected Resource</p>
                  <p className="font-mono text-xs">{selectedAlert.description}</p>
                </div>                
                <div className="text-xs text-muted-foreground">
                  {new Date(selectedAlert.created_at).toLocaleString()}
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
