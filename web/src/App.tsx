import {
  Activity,
  Archive,
  Boxes,
  Database,
  Globe2,
  Inbox,
  LayoutDashboard,
  LogOut,
  RefreshCw,
  Settings2,
  ShieldCheck,
  ShipWheel,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { authClient } from "@/lib/auth-client";
import type { PlatformState } from "@/lib/types";
import { api, cn, onActionError } from "@/lib/utils";
import { AuthScreen, MfaSetup } from "@/pages/Auth";
import { FrontAclView } from "@/pages/FrontAcl";
import {
  ActivityView,
  BackupsView,
  DatabasesView,
  DomainsView,
  EmailView,
  Overview,
  ProjectsView,
  ServicesView,
  SettingsView,
  UpdatesView,
} from "@/pages/Views";
import { Wizard } from "@/pages/Wizard";

const navigation = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "domains", label: "Domains & Endpoints", icon: Globe2 },
  { id: "projects", label: "Projects", icon: Boxes },
  { id: "databases", label: "Databases", icon: Database },
  { id: "email", label: "Email", icon: Inbox },
  { id: "services", label: "Services", icon: ShipWheel },
  { id: "activity", label: "Activity", icon: Activity },
  { id: "backups", label: "Backups", icon: Archive },
  { id: "updates", label: "Updates", icon: RefreshCw },
  { id: "front-acl", label: "Front door ACL", icon: ShieldCheck, ownerOnly: true },
  { id: "settings", label: "Settings", icon: Settings2 },
] as const;

type View = (typeof navigation)[number]["id"];

export function App() {
  const { data: session, isPending } = authClient.useSession();
  const [sessionResolved, setSessionResolved] = useState(false);
  const [view, setView] = useState<View>(
    () => navigation.find((item) => `#/${item.id}` === window.location.hash)?.id ?? "overview",
  );
  const [state, setState] = useState<PlatformState | null>(null);
  const [error, setError] = useState("");
  // Mutations dispatched by `act` report their failures here; without this a 403 from a
  // step-up-gated route would leave the button looking like it did nothing.
  const [actionError, setActionError] = useState<string | null>(null);
  const [mfaEnrollmentGate, setMfaEnrollmentGate] = useState(false);

  useEffect(() => {
    onActionError(setActionError);
    return () => onActionError(null);
  }, []);

  useEffect(() => {
    if (!isPending) setSessionResolved(true);
  }, [isPending]);

  useEffect(() => {
    const changed = () =>
      setView(navigation.find((item) => `#/${item.id}` === window.location.hash)?.id ?? "overview");
    window.addEventListener("hashchange", changed);
    return () => window.removeEventListener("hashchange", changed);
  }, []);

  const load = useCallback(async () => {
    try {
      setState(await api<PlatformState>("/api/state"));
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not load Ark Stack.");
    }
  }, []);

  useEffect(() => {
    if (session) void load();
  }, [session, load]);

  useEffect(() => {
    if (state && !state.setup.mfaAssured) setMfaEnrollmentGate(true);
  }, [state]);

  useEffect(() => {
    if (!state?.operations.some((item) => item.status === "queued" || item.status === "running")) return;
    const timer = window.setInterval(() => void load(), 2000);
    return () => window.clearInterval(timer);
  }, [state?.operations, load]);

  if (isPending && !sessionResolved) {
    return (
      <div className="grid min-h-screen place-items-center">
        <RefreshCw className="size-5 animate-spin text-muted-foreground" />
      </div>
    );
  }
  if (!session) return <AuthScreen />;
  if (state && (!state.setup.mfaAssured || mfaEnrollmentGate)) {
    return (
      <MfaSetup
        enrolled={state.setup.mfaEnrolled}
        onComplete={async () => {
          setMfaEnrollmentGate(false);
          await load();
        }}
      />
    );
  }
  if (state && !state.setup.wizardCompleted) return <Wizard onDone={load} />;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-primary">Ark Stack</p>
          <p className="mt-1 text-sm text-muted-foreground">Infrastructure desk</p>
        </div>
        <nav aria-label="Main navigation" className="space-y-1">
          {navigation
            .filter((item) => !("ownerOnly" in item) || state?.user.role === "owner")
            .map((item) => (
              <button
                key={item.id}
                className={cn("nav-item", view === item.id && "active")}
                onClick={() => {
                  setView(item.id);
                  window.location.hash = `/${item.id}`;
                }}
              >
                <item.icon className="size-4" aria-hidden="true" />
                {item.label}
              </button>
            ))}
        </nav>
        <div className="mt-auto flex items-center justify-between gap-2 rounded-xl border border-border p-3">
          <div className="min-w-0">
            <strong className="block truncate text-sm">{session.user.name}</strong>
            <small className="block truncate text-muted-foreground">{session.user.email}</small>
          </div>
          <Button
            variant="ghost"
            size="icon"
            aria-label="Sign out"
            onClick={() => void authClient.signOut().then(() => window.location.reload())}
          >
            <LogOut className="size-4" />
          </Button>
        </div>
      </aside>
      <main className="workspace">
        <header className="topbar">
          <div>
            <p className="text-xs uppercase tracking-[0.16em] text-muted-foreground">
              {navigation.find((item) => item.id === view)?.label}
            </p>
            <h1 className="display text-3xl">{navigation.find((item) => item.id === view)?.label}</h1>
          </div>
          <Button variant="outline" onClick={() => void load()}>
            <RefreshCw className="size-4" />
            Refresh
          </Button>
        </header>
        <div className="workspace-body">
          {error && <p className="mb-4 text-sm text-red-200">{error}</p>}
          {actionError && (
            <div
              className="mb-4 flex items-start justify-between gap-3 rounded-lg border border-red-300/30 bg-red-500/10 p-3 text-sm text-red-100"
              role="alert"
            >
              <span>{actionError}</span>
              <button
                type="button"
                className="shrink-0 underline"
                onClick={() => setActionError(null)}
                aria-label="Dismiss error"
              >
                Dismiss
              </button>
            </div>
          )}
          {!state ? (
            <RefreshCw className="size-5 animate-spin" />
          ) : (
            <ViewBody view={view} state={state} reload={load} />
          )}
        </div>
      </main>
    </div>
  );
}

function ViewBody({
  view,
  state,
  reload,
}: {
  view: View;
  state: PlatformState;
  reload: () => Promise<void>;
}) {
  if (view === "domains") return <DomainsView state={state} reload={reload} />;
  if (view === "projects") return <ProjectsView state={state} reload={reload} />;
  if (view === "databases") return <DatabasesView state={state} reload={reload} />;
  if (view === "email") return <EmailView state={state} reload={reload} />;
  if (view === "services") return <ServicesView state={state} reload={reload} />;
  if (view === "activity") return <ActivityView state={state} />;
  if (view === "backups") return <BackupsView state={state} reload={reload} />;
  if (view === "updates") return <UpdatesView state={state} reload={reload} />;
  if (view === "front-acl") return <FrontAclView state={state} />;
  if (view === "settings") return <SettingsView state={state} reload={reload} />;
  return <Overview state={state} reload={reload} />;
}
