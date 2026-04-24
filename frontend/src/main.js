import { startRouter, navigate } from "./router/router.js";
import { renderShell } from "./ui/layout/shell.js";
import { getState, setSession, logoutSession, subscribe, pushLiveNotification, setNotifications } from "./state/store.js";
import { isAuthed } from "./state/permissions.js";
import { me } from "./api/auth.js";
import { listNotifications } from "./api/notifications.js";
import { toast } from "./ui/components/toast.js";
import { CONFIG } from "./config.js";
import { loadTheme, applyTheme } from "./state/theme.js";
import { installKeybindings } from "./ui/keybindings.js";

let liveStream = null;

async function refreshNotifications() {
  try {
    const payload = await listNotifications({ page: 1, page_size: 25 });
    setNotifications(payload);
  } catch {
    // fail open; notification endpoints may be temporarily unavailable.
  }
}

function handleLiveEvent(evt, onToast) {
  const data = JSON.parse(evt.data || "{}");
  pushLiveNotification(data);
  if (onToast) onToast(data?.payload || {});
}

function startLiveNotificationStream() {
  if (liveStream) return;

  liveStream = new EventSource(`${CONFIG.API_BASE}/api/notifications/stream`, { withCredentials: true });

  liveStream.addEventListener("mention_notification_created", (evt) => {
    handleLiveEvent(evt, (payload) => {
      toast({ title: "Mention", message: payload?.notification?.message || "You were mentioned." });
    });
  });

  liveStream.addEventListener("rule_triggered", (evt) => {
    handleLiveEvent(evt, (payload) => {
      toast({
        title: "Rule triggered",
        message: `Vulnerability #${payload?.vulnerability_id || "?"} updated (${payload?.event_type || "event"}).`,
      });
    });
  });

  liveStream.addEventListener("scheduled_scan_escalation_logged", (evt) => {
    handleLiveEvent(evt, (payload) => {
      toast({
        title: "Escalation logged",
        message: `Vulnerability #${payload?.vulnerability_id || "?"} escalation step ${payload?.escalation_step || 0}.`,
      });
    });
  });

  liveStream.onerror = () => {
    if (liveStream) {
      liveStream.close();
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
    setSession({
      user,
      token: state.session.token,
      refreshToken: state.session.refreshToken,
      teams: user?.teams || [],
      currentTeamId: user?.current_team_id ?? state.session.currentTeamId ?? null,
    });
  } catch {
    // token invalid/expired, etc.
    logoutSession();
    toast({ title: "Session expired", message: "Please log in again." });
    navigate("/login");
  }
}

function boot() {
  // Apply saved or OS-preferred theme before first render
  applyTheme(loadTheme());

  // rerender header/sidebar on state changes
  subscribe((state) => {
    renderShell();
    const role = state?.session?.user?.role;
    if (role) {
      document.body.setAttribute("data-user-role", role);
    } else {
      document.body.removeAttribute("data-user-role");
    }
    if (isAuthed(state)) {
      startLiveNotificationStream();
    } else {
      stopLiveNotificationStream();
    }
  });

  renderShell();
  installKeybindings();
  startRouter();
  refreshSessionFromServer();
  if (isAuthed(getState())) {
    startLiveNotificationStream();
    refreshNotifications();
  }
}

boot();
