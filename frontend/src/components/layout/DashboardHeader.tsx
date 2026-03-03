import { Bell, ScrollText, Menu } from "lucide-react";
import { Link } from "react-router-dom";
import { alerts, activityLogs } from "@/data/mockData";
import { useEffect, useState } from "react";



interface DashboardHeaderProps {
  onToggleSidebar: () => void;
}

export function DashboardHeader({ onToggleSidebar }: DashboardHeaderProps) {
  const [alerts, setAlerts] = useState<any[]>([]);
const [lastSeenCount, setLastSeenCount] = useState<number>(() => {
  return Number(localStorage.getItem("lastSeenCount") || 0);
});
  const openAlerts = alerts.filter((a) => a.status === "open").length;
const newAlertsCount =
  alerts.length > lastSeenCount
    ? alerts.length - lastSeenCount
    : 0;
useEffect(() => {
  const fetchAlerts = async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/alerts");
      const data = await res.json();
      setAlerts(data);
      if (lastSeenCount > data.length) {
  setLastSeenCount(data.length);
  localStorage.setItem("lastSeenCount", String(data.length));
}
    } catch (err) {
      console.error(err);
    }
  };

  fetchAlerts(); // initial load

  const handleNewAlert = () => {
    fetchAlerts();
  };

  window.addEventListener("new-alert", handleNewAlert);

  return () => {
    window.removeEventListener("new-alert", handleNewAlert);
  };
}, []);
  return (
    <header className="flex h-16 items-center justify-between border-b border-border/30 px-6 glass-card rounded-none border-x-0 border-t-0">
      <div className="flex items-center gap-4">
        <button onClick={onToggleSidebar} className="text-muted-foreground hover:text-foreground transition-colors lg:hidden">
          <Menu className="h-5 w-5" />
        </button>
        <h2 className="text-sm font-medium text-muted-foreground">Multicloud Security Command Center</h2>
      </div>

      <div className="flex items-center gap-2">
        <Link
          to="/activity-logs"
          className="relative flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground"
        >
          <ScrollText className="h-4 w-4" />
          <span className="hidden sm:inline">Logs</span>
          <span className="flex h-5 min-w-5 items-center justify-center rounded-full bg-primary/20 px-1.5 text-[10px] font-bold text-primary">
            {activityLogs.length}
          </span>
        </Link>

        <Link
          to="/alerts"
          className="relative flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground"
        >
          <div
  className="relative cursor-pointer"
  onClick={() => {
  setLastSeenCount(alerts.length);
  localStorage.setItem("lastSeenCount", String(alerts.length));
}}
  >
  <Bell className="h-5 w-5" />
  {newAlertsCount > 0 && (
    <span className="absolute -top-1 -right-1 translate-x-1/2 -translate-y-1/2 bg-red-600 text-white text-[9px] min-w-[16px] h-[16px] flex items-center justify-center rounded-full px-1.5 font-bold">
      {newAlertsCount}
    </span>
  )}
</div>
        </Link>
      </div>
    </header>
  );
}
