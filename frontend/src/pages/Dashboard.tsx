import { Link } from "react-router-dom";
import {
  AlertTriangle,
  ShieldAlert,
  Server,
  TrendingUp,
  Activity,
  ScrollText,
  Bell,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import {
  alerts,
  activityLogs,
  cloudStats,
  alertsTrendData,
  threatCategoryData,
  severityBreakdown,
  cloudProviderInfo,
  type CloudProvider,
} from "@/data/mockData";
import { SeverityBadge, CloudBadge, StatusBadge } from "@/components/dashboard/Badges";
import { testBackend } from "@/lib/api";
import { useEffect, useState } from "react";
import { getAlerts } from "@/lib/api";

const cloudKeys: CloudProvider[] = ["aws", "azure", "gcp"];
export default function Dashboard() {
  const [alerts, setAlerts] = useState<any[]>([]);
  const fetchAlerts = async () => {
  try {
    const data = await getAlerts();
    setAlerts(data);
  } catch (error) {
    console.error("Failed to fetch alerts", error);
  }
};
const generateRandomAlert = async () => {
  try {
    await fetch("http://localhost:8000/simulator/trigger/random", {
      method: "POST",
    });

    await fetchAlerts();
  } catch (error) {
    console.error("Failed to generate alert", error);
  }
};
  const totalAlerts = alerts.length;
  const criticalAlerts = alerts.filter(a => a.severity === "critical").length;
  const totalResources = cloudStats.reduce((s, c) => s + c.activeResources, 0);
  
useEffect(() => {
  const loadAlerts = async () => {
    try {
      const data = await getAlerts();
      console.log("ALERTS:", data);
      setAlerts(data);
    } catch (error) {
      console.error("Failed to load alerts", error);
    }
  };


  loadAlerts();
}, []);
  return (
      <div className="space-y-6">
      {/* Page title */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Security Overview</h1>
        <p className="text-sm text-muted-foreground mt-1">Multicloud threat monitoring and analysis</p>
      </div>
    <button
  onClick={async () => {
    try {
      const status = await testBackend();
      console.log("Response:", status);
      alert("Backend Response: " + JSON.stringify(status));
    } catch (error) {
      console.error("ERROR:", error);
      alert("ERROR - Check Console");
    }
  }}
  className="px-4 py-2 bg-black text-white rounded"
>
  Test Backend
</button>
<button
  onClick={generateRandomAlert}
  className="px-4 py-2 bg-black text-white rounded-md hover:bg-red-700"
>
  Generate Random Alert
</button>
      {/* Cloud Provider Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {cloudKeys.map((cloud) => {
          const stats = {
          totalAlerts: alerts.filter(a => a.cloud.toLowerCase() === cloud).length,
          criticalAlerts: alerts.filter(a => a.cloud.toLowerCase() === cloud && a.severity === "critical").length,
          activeResources: 0
        };
          const info = cloudProviderInfo[cloud];
          return (
            <Link
              key={cloud}
              to={`/cloud/${cloud}`}
              className="glass-card-hover p-5 flex flex-col gap-4 group"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div
                    className="h-10 w-10 rounded-lg flex items-center justify-center text-lg font-bold"
                    style={{ backgroundColor: `${info.color}20`, color: info.color }}
                  >
                    {info.short[0]}
                  </div>
                  <div>
                    <p className="font-semibold text-foreground">{info.short}</p>
                    <p className="text-[11px] text-muted-foreground">{info.name}</p>
                  </div>
                </div>
                <TrendingUp className="h-4 w-4 text-muted-foreground group-hover:text-primary transition-colors" />
              </div>
              <div className="grid grid-cols-3 gap-3 text-center">
                <div>
                  <p className="text-lg font-bold text-foreground">{stats.totalAlerts}</p>
                  <p className="text-[10px] text-muted-foreground">Alerts</p>
                </div>
                <div>
                  <p className="text-lg font-bold text-severity-critical">{stats.criticalAlerts}</p>
                  <p className="text-[10px] text-muted-foreground">Critical</p>
                </div>
                <div>
                  <p className="text-lg font-bold text-foreground">{stats.activeResources}</p>
                  <p className="text-[10px] text-muted-foreground">Resources</p>
                </div>
              </div>
            </Link>
          );
        })}
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Alerts", value: totalAlerts, icon: Bell, accent: "text-severity-high" },
          { label: "Critical", value: criticalAlerts, icon: ShieldAlert, accent: "text-severity-critical" },
          { label: "Resources", value: totalResources, icon: Server, accent: "text-primary" },
          { label: "Activity Events", value: activityLogs.length, icon: Activity, accent: "text-severity-medium" },
        ].map((s) => (
          <div key={s.label} className="glass-card p-4 flex items-center gap-4">
            <div className="h-10 w-10 rounded-lg bg-secondary flex items-center justify-center">
              <s.icon className={`h-5 w-5 ${s.accent}`} />
            </div>
            <div>
              <p className="text-2xl font-bold">{s.value}</p>
              <p className="text-[11px] text-muted-foreground">{s.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Alerts Trend */}
        <div className="glass-card p-5 lg:col-span-2">
          <h3 className="text-sm font-semibold mb-4">Alerts Trend (7 Days)</h3>
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={alertsTrendData}>
              <defs>
                <linearGradient id="awsGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(var(--aws))" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="hsl(var(--aws))" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="azureGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(var(--azure))" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="hsl(var(--azure))" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gcpGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(var(--gcp))" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="hsl(var(--gcp))" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
              <XAxis dataKey="date" tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} />
              <YAxis tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(var(--popover))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: 8,
                  fontSize: 12,
                }}
              />
              <Area type="monotone" dataKey="aws" stroke="hsl(var(--aws))" fill="url(#awsGrad)" strokeWidth={2} />
              <Area type="monotone" dataKey="azure" stroke="hsl(var(--azure))" fill="url(#azureGrad)" strokeWidth={2} />
              <Area type="monotone" dataKey="gcp" stroke="hsl(var(--gcp))" fill="url(#gcpGrad)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Breakdown */}
        <div className="glass-card p-5">
          <h3 className="text-sm font-semibold mb-4">Severity Breakdown</h3>
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie data={severityBreakdown} cx="50%" cy="50%" innerRadius={55} outerRadius={85} dataKey="value" stroke="none">
                {severityBreakdown.map((entry, i) => (
                  <Cell key={i} fill={entry.fill} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(var(--popover))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: 8,
                  fontSize: 12,
                }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex flex-wrap gap-3 justify-center mt-2">
            {severityBreakdown.map((s) => (
              <div key={s.name} className="flex items-center gap-1.5 text-[11px]">
                <span className="h-2 w-2 rounded-full" style={{ backgroundColor: s.fill }} />
                <span className="text-muted-foreground">{s.name}: {s.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Threats by category */}
      <div className="glass-card p-5">
        <h3 className="text-sm font-semibold mb-4">Threats by Category</h3>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={threatCategoryData}>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
            <XAxis dataKey="category" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
            <YAxis tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} />
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(var(--popover))",
                border: "1px solid hsl(var(--border))",
                borderRadius: 8,
                fontSize: 12,
              }}
            />
            <Bar dataKey="count" radius={[6, 6, 0, 0]}>
              {threatCategoryData.map((entry, i) => (
                <Cell key={i} fill={entry.fill} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Recent Alerts + Activity Logs side by side */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recent Alerts */}
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-severity-high" />
              Recent Alerts
            </h3>
            <Link to="/alerts" className="text-[11px] text-primary hover:underline">View all</Link>
          </div>
          <div className="space-y-3 max-h-[320px] overflow-auto scrollbar-thin pr-1">
            {alerts.slice(0, 6).map((alert) => (
              <div key={alert.id} className="flex items-start gap-3 rounded-lg bg-secondary/30 p-3">
                <div className="mt-0.5">
                  <SeverityBadge severity={alert.severity} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{alert.title}</p>
                  <p className="text-[11px] text-muted-foreground mt-0.5">{alert.resource}</p>
                </div>
                <div className="flex flex-col items-end gap-1">
                  <CloudBadge cloud={alert.cloud} />
                  <span className="text-[10px] text-muted-foreground whitespace-nowrap">
                    {new Date(alert.create_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Activity Logs */}
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold flex items-center gap-2">
              <ScrollText className="h-4 w-4 text-primary" />
              Recent Activity
            </h3>
            <Link to="/activity-logs" className="text-[11px] text-primary hover:underline">View all</Link>
          </div>
          <div className="space-y-3 max-h-[320px] overflow-auto scrollbar-thin pr-1">
            {activityLogs.slice(0, 6).map((log) => (
              <div key={log.id} className="flex items-start gap-3 rounded-lg bg-secondary/30 p-3">
                <span
                  className={`mt-1 h-2 w-2 rounded-full shrink-0 ${
                    log.status === "success"
                      ? "bg-primary"
                      : log.status === "failure"
                      ? "bg-severity-critical"
                      : "bg-severity-medium"
                  }`}
                />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium font-mono truncate">{log.action}</p>
                  <p className="text-[11px] text-muted-foreground mt-0.5">{log.user}</p>
                </div>
                <div className="flex flex-col items-end gap-1">
                  <CloudBadge cloud={log.cloud} />
                  <span className="text-[10px] text-muted-foreground whitespace-nowrap">
                    {new Date(log.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
