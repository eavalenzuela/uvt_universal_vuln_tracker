import { startRouter, navigate } from "./router/router.js";
import { renderShell } from "./ui/layout/shell.js";
import { getState, setSession, logoutSession, subscribe } from "./state/store.js";
import { isAuthed } from "./state/permissions.js";
import { me } from "./api/auth.js";
import { toast } from "./ui/components/toast.js";

async function refreshSessionFromServer() {
  const state = getState();
  if (!isAuthed(state)) return;

  try {
    const user = await me();
    setSession({ token: state.session.token, user });
  } catch {
    // token invalid/expired, etc.
    logoutSession();
    toast({ title: "Session expired", message: "Please log in again." });
    navigate("/login");
  }
}

function boot() {
  // rerender header/sidebar on state changes
  subscribe(() => renderShell());

  renderShell();
  startRouter();
  refreshSessionFromServer();
}

boot();
