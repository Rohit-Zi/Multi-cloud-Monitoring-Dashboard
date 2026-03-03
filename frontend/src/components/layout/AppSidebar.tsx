import {
  LayoutDashboard,
  AlertTriangle,
  ScrollText,
  Cloud,
  Shield,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { NavLink } from "@/components/NavLink";
import { cn } from "@/lib/utils";

const navItems = [
  { title: "Dashboard", url: "/", icon: LayoutDashboard },
  { title: "Alerts", url: "/alerts", icon: AlertTriangle },
  { title: "Activity Logs", url: "/activity-logs", icon: ScrollText },
];

const cloudItems = [
  { title: "AWS", url: "/cloud/aws", color: "text-aws" },
  { title: "Azure", url: "/cloud/azure", color: "text-azure" },
  { title: "GCP", url: "/cloud/gcp", color: "text-gcp" },
];

interface AppSidebarProps {
  open: boolean;
  onToggle: () => void;
}

export function AppSidebar({ open, onToggle }: AppSidebarProps) {
  return (
    <aside
      className={cn(
        "glass-sidebar flex flex-col transition-all duration-300 shrink-0",
        open ? "w-60" : "w-16"
      )}
    >
      {/* Logo area */}
      <div className="flex h-16 items-center gap-3 px-4 border-b border-border/30">
        <Shield className="h-7 w-7 text-primary shrink-0" />
        {open && (
          <span className="text-lg font-bold tracking-tight text-foreground whitespace-nowrap">
            CloudGuard
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 space-y-1 px-2">
        <p className={cn("text-[10px] uppercase tracking-widest text-muted-foreground mb-2", open ? "px-3" : "px-1 text-center")}>
          {open ? "Monitor" : "•"}
        </p>
        {navItems.map((item) => (
          <NavLink
            key={item.url}
            to={item.url}
            end={item.url === "/"}
            className={cn(
              "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground",
              !open && "justify-center px-0"
            )}
            activeClassName="bg-primary/10 text-primary border border-primary/20"
          >
            <item.icon className="h-4 w-4 shrink-0" />
            {open && <span>{item.title}</span>}
          </NavLink>
        ))}

        <div className="my-4 border-t border-border/30" />

        <p className={cn("text-[10px] uppercase tracking-widest text-muted-foreground mb-2", open ? "px-3" : "px-1 text-center")}>
          {open ? "Clouds" : "☁"}
        </p>
        {cloudItems.map((item) => (
          <NavLink
            key={item.url}
            to={item.url}
            className={cn(
              "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground",
              !open && "justify-center px-0"
            )}
            activeClassName="bg-primary/10 text-primary border border-primary/20"
          >
            <Cloud className={cn("h-4 w-4 shrink-0", item.color)} />
            {open && <span>{item.title}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Collapse toggle */}
      <button
        onClick={onToggle}
        className="flex items-center justify-center h-12 border-t border-border/30 text-muted-foreground hover:text-foreground transition-colors"
      >
        {open ? <ChevronLeft className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
      </button>
    </aside>
  );
}
