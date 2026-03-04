import { useState, useMemo, useEffect } from "react";
import { CloudBadge } from "@/components/dashboard/Badges";
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
import { Search, CheckCircle, XCircle, AlertTriangle } from "lucide-react";
import { getLogs } from "@/lib/api";

export default function ActivityLogsPage() {
  const [cloudFilter, setCloudFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [logs, setLogs] = useState<any[]>([]);
  useEffect(() => {
  const loadLogs = async () => {
    try {
      const data = await getLogs();
      setLogs(data);
    } catch (err) {
      console.error(err);
    }
  };

  loadLogs();
}, []);

  const sanitizeSearch = (value: string) => {
    return value.replace(/[<>"'&]/g, "").slice(0, 100);
  };
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    return logs.filter((l) => {
      if (cloudFilter !== "all" && l.cloud !== cloudFilter) return false;
      if (statusFilter !== "all" && l.outcome?.toLowerCase() !== statusFilter) return false;
      if (
        search &&
        !l.event_name?.toLowerCase().includes(search.toLowerCase()) &&
        !l.user?.toLowerCase().includes(search.toLowerCase())) 
        return false;
      return true;
    });
  }, [logs, cloudFilter, statusFilter, search]);

  const StatusIcon = ({ status }: { status: string }) => {
    if (status === "success") return <CheckCircle className="h-4 w-4 text-primary" />;
    if (status === "failure") return <XCircle className="h-4 w-4 text-severity-critical" />;
    return <AlertTriangle className="h-4 w-4 text-severity-medium" />;
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Activity Logs</h1>
        <p className="text-sm text-muted-foreground mt-1">Track all actions and events across your cloud infrastructure</p>
      </div>

      {/* Filters */}
      <div className="glass-card p-4 flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            value={search}
            onChange={(e) => setSearch(sanitizeSearch(e.target.value))}
            placeholder="Search actions or users..."
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
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-[120px] bg-secondary/50 border-border/50"><SelectValue placeholder="Status" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All</SelectItem>
            <SelectItem value="success">Success</SelectItem>
            <SelectItem value="failure">Failure</SelectItem>
            <SelectItem value="warning">Warning</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <div className="glass-card overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="border-border/30 hover:bg-transparent">
              <TableHead className="text-muted-foreground w-8"></TableHead>
              <TableHead className="text-muted-foreground">Action</TableHead>
              <TableHead className="text-muted-foreground">User</TableHead>
              <TableHead className="text-muted-foreground">Cloud</TableHead>
              <TableHead className="text-muted-foreground">Category</TableHead>
              <TableHead className="text-muted-foreground">Resource</TableHead>
              <TableHead className="text-muted-foreground">IP</TableHead>
              <TableHead className="text-muted-foreground">Time</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map((log) => (
              <>
                <TableRow
                  key={log.log_id}
                  className="border-border/20 cursor-pointer hover:bg-secondary/30"
                  onClick={() => setExpandedId(expandedId === log.log_id ? null : log.log_id)}
                >
                  <TableCell>
                    <StatusIcon status={log.outcome?.toLowerCase()} />
                  </TableCell>
                  <TableCell>
                    <p className="font-mono text-sm font-medium">{log.event_name}</p>
                    <p className="text-[10px] text-muted-foreground">{log.log_id}</p>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{log.user}</TableCell>
                  <TableCell><CloudBadge cloud={log.cloud?.toLowerCase()} /></TableCell>
                  <TableCell>
                  <span className="px-2 py-1 text-[10px] rounded bg-secondary text-muted-foreground">
                    {log.event_category}
                  </span>
                </TableCell>
                  <TableCell className="text-xs text-muted-foreground font-mono">{log.resource}</TableCell>
                  <TableCell className="text-xs text-muted-foreground font-mono">{log.source_ip}</TableCell>
                  <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                    {new Date(log.timestamp).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                  </TableCell>
                </TableRow>
                {expandedId === log.log_id && (
                  <TableRow key={`${log.log_id}-detail`} className="border-border/20 bg-secondary/20">
                    <TableCell colSpan={7} className="text-sm">
                      <pre className="text-xs whitespace-pre-wrap">{log.raw_log}</pre>
                      <p>{log.details}</p>
                    </TableCell>
                  </TableRow>
                )}
              </>
            ))}
          </TableBody>
        </Table>
        {filtered.length === 0 && (
          <div className="flex items-center justify-center py-12 text-muted-foreground text-sm">No logs found</div>
        )}
      </div>
    </div>
  );
}
