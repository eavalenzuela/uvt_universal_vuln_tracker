import { startRouter, navigate } from "./router/router.js";
import { renderShell } from "./ui/layout/shell.js";
import { getState, setSession, logoutSession, subscribe, pushLiveNotification } from "./state/store.js";
import { isAuthed } from "./state/permissions.js";
import { me } from "./api/auth.js";
import { toast } from "./ui/components/toast.js";
import { CONFIG } from "./config.js";

let liveStream = null;

function startLiveNotificationStream() {
  const token = getState()?.session?.token;
  if (!token) return;
  if (liveStream) return;

  const streamUrl = `${CONFIG.API_BASE}/api/notifications/stream?token=${encodeURIComponent(token)}`;
  liveStream = new EventSource(streamUrl, { withCredentials: true });

  liveStream.addEventListener("mention_notification_created", (evt) => {
    const data = JSON.parse(evt.data || "{}");
    const payload = data?.payload || {};
    pushLiveNotification(data);
    toast({ title: "Mention", message: payload?.notification?.message || "You were mentioned." });
  });

  liveStream.addEventListener("rule_triggered", (evt) => {
    const data = JSON.parse(evt.data || "{}");
    const payload = data?.payload || {};
    pushLiveNotification(data);
    toast({
      title: "Rule triggered",
      message: `Vulnerability #${payload?.vulnerability_id || "?"} updated (${payload?.event_type || "event"}).`,
    });
  });

  liveStream.addEventListener("scheduled_scan_escalation_logged", (evt) => {
    const data = JSON.parse(evt.data || "{}");
    const payload = data?.payload || {};
    pushLiveNotification(data);
    toast({
      title: "Escalation logged",
      message: `Vulnerability #${payload?.vulnerability_id || "?"} escalation step ${payload?.escalation_step || 0}.`,
    });
  });

  liveStream.onerror = () => {
    if (liveStream?.readyState === EventSource.CLOSED) {
      liveStream = null;
    }
  };
}

function stopLiveNotificationStream() {
  if (!liveStream) return;
  liveStream.close();
  liveStream = null;
}

async function refreshSessionFromServer() {
  const state = getState();
  if (!isAuthed(state)) return;

  try {
    const user = await me();
    setSession({ token: state.session.token, refreshToken: state.session.refreshToken, user });
  } catch {
    // token invalid/expired, etc.
    logoutSession();
    toast({ title: "Session expired", message: "Please log in again." });
    navigate("/login");
  }
}

function boot() {
  // rerender header/sidebar on state changes
  subscribe((state) => {
    renderShell();
    if (isAuthed(state)) {
      startLiveNotificationStream();
    } else {
      stopLiveNotificationStream();
    }
  });

  renderShell();
  startRouter();
  refreshSessionFromServer();
  if (isAuthed(getState())) {
    startLiveNotificationStream();
  }
}

boot();
