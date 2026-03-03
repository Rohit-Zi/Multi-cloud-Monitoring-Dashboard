import { Bell, ScrollText, Menu } from "lucide-react";
import { Link } from "react-router-dom";
import { alerts, activityLogs } from "@/data/mockData";

interface DashboardHeaderProps {
  onToggleSidebar: () => void;
}

export function DashboardHeader({ onToggleSidebar }: DashboardHeaderProps) {
  const openAlerts = alerts.filter((a) => a.status === "open").length;

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
          <Bell className="h-4 w-4" />
          <span className="hidden sm:inline">Alerts</span>
          {openAlerts > 0 && (
            <span className="flex h-5 min-w-5 items-center justify-center rounded-full bg-severity-critical px-1.5 text-[10px] font-bold text-white animate-pulse-glow">
              {openAlerts}
            </span>
          )}
        </Link>
      </div>
    </header>
  );
}
