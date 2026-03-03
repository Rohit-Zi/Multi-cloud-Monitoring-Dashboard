import { useParams, Navigate } from "react-router-dom";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useEffect, useState } from "react";
import { getAlerts } from "@/lib/api";
import {
  cloudProviderInfo,
} from "@/data/mockData";
import { SeverityBadge, StatusBadge, CloudBadge, ResourceStatusDot } from "@/components/dashboard/Badges";
import { Progress } from "@/components/ui/progress";

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
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { ShieldAlert, Server, Shield, AlertTriangle, Activity, CheckCircle, XCircle } from "lucide-react";


const validClouds = ["aws", "azure", "gcp"];


export default function CloudDetailPage() {
  const { provider } = useParams<{ provider: string }>();
  const [alerts, setAlerts] = useState<any[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<any | null>(null);
useEffect(() => {
  const loadAlerts = async () => {
    try {
      const data = await getAlerts();
      setAlerts(data);
    } catch (err) {
      console.error(err);
    }
  };

  loadAlerts();
}, []);
  if (!provider || !validClouds.includes(provider)) return <Navigate to="/" />;

  const cloud = provider as keyof typeof cloudProviderInfo;
  const info = cloudProviderInfo[cloud];
   const cloudAlerts = alerts.filter(
  (a) => a.cloud.toLowerCase() === provider?.toLowerCase()
);
  const stats = {
  totalAlerts: cloudAlerts.length,
  criticalAlerts: cloudAlerts.filter(a => a.severity === "high").length,
  activeResources: 7, //temp value here, should come from API
  complianceScore: 79, //temp value here, should come from API
  threatScore: Math.min(100, cloudAlerts.length * 3)
};
 
  const cloudLogs: any[] = [];
  const cloudResources: any[] = [];
  const cloudCompliance: any[] = [];

  const trendMap: Record<string, number> = {};

cloudAlerts.forEach((alert) => {
  const date = new Date(alert.created_at || Date.now())
    .toISOString()
    .split("T")[0];

  trendMap[date] = (trendMap[date] || 0) + 1;
});
const trendData = Object.entries(trendMap)
  .map(([date, count]) => ({ date, alerts: count }))
  .sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());

const [severityFilter, setSeverityFilter] = useState<string>("all");
const [statusFilter, setStatusFilter] = useState<string>("all");
const [search, setSearch] = useState("");
const filteredAlerts = cloudAlerts.filter((a) => {
  const searchLower = search.toLowerCase();

  const matchesSearch =
    a.title?.toLowerCase().includes(searchLower) ||
    a.resource?.toLowerCase().includes(searchLower);

  const matchesSeverity =
    severityFilter === "all" || a.severity === severityFilter;

  const matchesStatus =
    statusFilter === "all" || a.status === statusFilter;

  return matchesSearch && matchesSeverity && matchesStatus;
});const sanitizeSearch = (value: string) => {
    return value.replace(/[<>"'&]/g, "").slice(0, 100);
  };


  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <div
          className="h-14 w-14 rounded-xl flex items-center justify-center text-2xl font-bold"
          style={{ backgroundColor: `${info.color}20`, color: info.color }}
        >
          {info.short[0]}
        </div>
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{info.name}</h1>
          <p className="text-sm text-muted-foreground">Security overview for {info.short}</p>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { label: "Total Alerts", value: stats.totalAlerts, icon: AlertTriangle, color: "text-severity-high" },
          { label: "Critical", value: stats.criticalAlerts, icon: ShieldAlert, color: "text-severity-critical" },
          { label: "Resources", value: stats.activeResources, icon: Server, color: "text-primary" },
          { label: "Compliance", value: `${stats.complianceScore}%`, icon: Shield, color: "text-severity-medium" },
          { label: "Threat Score", value: stats.threatScore, icon: Activity, color: stats.threatScore > 70 ? "text-severity-critical" : "text-severity-medium" },
        ].map((s) => (
          <div key={s.label} className="glass-card p-4 flex items-center gap-3">
            <s.icon className={`h-5 w-5 ${s.color}`} />
            <div>
              <p className="text-xl font-bold">{s.value}</p>
              <p className="text-[10px] text-muted-foreground">{s.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="bg-secondary/50 border border-border/30">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
          <TabsTrigger value="logs">Activity Logs ({cloudLogs.length})</TabsTrigger>
          <TabsTrigger value="resources">Resources ({cloudResources.length})</TabsTrigger>
          <TabsTrigger value="compliance">Compliance</TabsTrigger>
        </TabsList>

        {/* OVERVIEW */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold mb-4">Alerts Trend</h3>
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={trendData}>
                  <defs>
                    <linearGradient id={`${cloud}DetailGrad`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={info.color} stopOpacity={0.3} />
                      <stop offset="95%" stopColor={info.color} stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="date" tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} />
                  <YAxis tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} />
                  <Tooltip contentStyle={{ backgroundColor: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} />
                  <Area type="monotone" dataKey="alerts" stroke={info.color} fill={`url(#${cloud}DetailGrad)`} strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold mb-4">Top Alerts</h3>
              <div className="space-y-3">
                {cloudAlerts.slice(0, 5).map((a) => (
                  <div key={a.id} className="flex items-center gap-3 rounded-lg bg-secondary/30 p-3">
                    <SeverityBadge severity={a.severity} />
                    <p className="text-sm flex-1 truncate">{a.title}</p>
                    <StatusBadge status={a.status} />
                  </div>
                ))}
              </div>
            </div>
          </div>
        </TabsContent>

      {/* ALERTS */}
      
        <TabsContent value="alerts">

          <div className="glass-card p-4 flex flex-wrap gap-3 items-center mb-4">
            <div className="relative flex-1 min-w-[200px]">
          <input
            value={search}
          onChange={(e) => setSearch(sanitizeSearch(e.target.value))}
          placeholder="Search alerts..."
          className="w-full bg-secondary/50 rounded-lg px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground outline-none border border-border/50 focus:border-primary/50"
        />
        </div>
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger className="w-[130px] bg-secondary/50 border-border/50">
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>

          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-[130px] bg-secondary/50 border-border/50">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="detected">Detected</SelectItem>
              <SelectItem value="investigating">Investigating</SelectItem>
              <SelectItem value="resolved">Resolved</SelectItem>
            </SelectContent>
          </Select>
        </div>

  <div className="glass-card h-[500px] flex flex-col">
    {/* HEADER TABLE (STATIC) */}
    <Table className="table-fixed w-full">
      <TableHeader>
        <TableRow className="border-border/30 hover:bg-transparent">
          <TableHead className=" w-[40%] text-muted-foreground">Alert</TableHead>
          <TableHead className=" w-[15%] text-muted-foreground">Severity {severityFilter !== "all" && `(${filteredAlerts.length})`}</TableHead>
          <TableHead className=" w-[15%] text-muted-foreground">Status {statusFilter !== "all" && `(${filteredAlerts.length})`}</TableHead>
          <TableHead className=" w-[15%] text-muted-foreground">Resource</TableHead>
          <TableHead className=" w-[15%] text-muted-foreground">Time</TableHead>
        </TableRow>
      </TableHeader>
    </Table>
    <div className="flex-1 overflow-y-auto scrollbar-thin scrollbar-thumb-border scrollbar-track-transparent">
      <Table className="table-fixed w-full">
        <TableBody>
          {filteredAlerts.map((a) => (
            <TableRow
              key={a.id}
              className="border-border/20 hover:bg-secondary/30 cursor-pointer"
              onClick={() => setSelectedAlert(a)}
            >
              <TableCell className="w-[40%]">
                <p className="font-medium text-sm">{a.title}</p>
                <p className="text-[10px] text-muted-foreground">
                  ALT-{a.id.slice(0, 6).toUpperCase()}
                </p>
              </TableCell>
              <TableCell className="w-[15%]"><SeverityBadge severity={a.severity} /></TableCell>
              <TableCell className="w-[15%]"><StatusBadge status={a.status} /></TableCell>
              <TableCell className="w-[15%] text-xs text-muted-foreground font-mono">
                {a.resource}
              </TableCell>
              <TableCell className="w-[15%] text-xs text-muted-foreground whitespace-nowrap">
                {new Date(a.created_at).toLocaleString([], {
                  month: "short",
                  day: "numeric",
                  hour: "2-digit",
                  minute: "2-digit",
                })}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>

  </div>
</TabsContent>

        {/* ACTIVITY LOGS */}
        <TabsContent value="logs">
          <div className="glass-card overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="border-border/30 hover:bg-transparent">
                  <TableHead className="text-muted-foreground w-8"></TableHead>
                  <TableHead className="text-muted-foreground">Action</TableHead>
                  <TableHead className="text-muted-foreground">User</TableHead>
                  <TableHead className="text-muted-foreground">Resource</TableHead>
                  <TableHead className="text-muted-foreground">Time</TableHead>
                </TableRow>
              </TableHeader>
              <div className="glass-card p-4 flex flex-wrap gap-3 items-center">
              </div>          
              <TableBody>
                {cloudLogs.map((l) => (
                  <TableRow key={l.id} className="border-border/20 hover:bg-secondary/30">
                    <TableCell>
                      {l.status === "success" ? <CheckCircle className="h-4 w-4 text-primary" /> : l.status === "failure" ? <XCircle className="h-4 w-4 text-severity-critical" /> : <AlertTriangle className="h-4 w-4 text-severity-medium" />}
                    </TableCell>
                    <TableCell className="font-mono text-sm">{l.action}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{l.user}</TableCell>
                    <TableCell className="text-xs text-muted-foreground font-mono">{l.resource}</TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">{new Date(l.timestamp).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </TabsContent>

        {/* RESOURCES */}
        <TabsContent value="resources">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {cloudResources.map((r) => (
              <div key={r.id} className="glass-card p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-semibold">{r.name}</p>
                  <ResourceStatusDot status={r.status} />
                </div>
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span className="capitalize">{r.type}</span>
                  <span>•</span>
                  <span>{r.region}</span>
                </div>
                <p className="text-[10px] uppercase tracking-wide text-muted-foreground capitalize">{r.status}</p>
              </div>
            ))}
          </div>
        </TabsContent>

        {/* COMPLIANCE */}
        <TabsContent value="compliance">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {cloudCompliance.map((c) => (
              <div key={c.framework} className="glass-card p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-semibold">{c.framework}</h4>
                  <span className={`text-lg font-bold ${c.score >= 80 ? "text-primary" : c.score >= 70 ? "text-severity-medium" : "text-severity-high"}`}>
                    {c.score}%
                  </span>
                </div>
                <Progress value={c.score} className="h-2" />
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span className="text-primary">{c.passed} passed</span>
                  <span className="text-severity-critical">{c.failed} failed</span>
                  <span>{c.total} total</span>
                </div>
              </div>
            ))}
          </div>
        </TabsContent>
      </Tabs>
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
