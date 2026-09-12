import { Component, type ErrorInfo, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { FirewallShell } from "./components/firewall/shell";
import "./styles.css";

class ErrorBoundary extends Component<{ children: ReactNode }, { error: string | null }> {
  state: { error: string | null } = { error: null };
  static getDerivedStateFromError(error: Error) { return { error: error.message }; }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error("Limen UI error", error, info); }
  render() {
    if (this.state.error) return <main className="mx-auto max-w-xl p-8 text-fg" role="alert">
      <h1 className="text-xl font-medium">Limen konnte nicht geladen werden / Could not load</h1>
      <p className="my-4 text-muted">{this.state.error}</p>
      <p className="text-sm text-muted">Windows-Firewall-Regeln bleiben bestehen. / Windows Firewall rules remain in place.</p>
      <button className="mt-4 rounded border border-border p-3" onClick={() => location.reload()}>Neu laden / Reload</button>
    </main>;
    return this.props.children;
  }
}

createRoot(document.getElementById("app")!).render(<ErrorBoundary><FirewallShell /></ErrorBoundary>);
