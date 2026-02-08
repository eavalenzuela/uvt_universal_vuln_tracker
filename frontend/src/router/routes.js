import { requireAuth, requireRole } from "./guards.js";
import { LoginView } from "../views/login/loginView.js";
import { DashboardView } from "../views/dashboard/dashboardView.js";
import { VulnListView } from "../views/vulnerabilities/vulnListView.js";
import { VulnDetailView } from "../views/vulnerabilities/vulnDetailView.js";
import { AdminUsersView } from "../views/admin/adminUsersView.js";
import { AdminLogsView } from "../views/admin/adminLogsView.js";
import { AdminPluginsView } from "../views/admin/adminPluginsView.js";
import { AdminNotificationRulesView } from "../views/admin/adminNotificationRulesView.js";
import { AdminNotificationDeliveryView } from "../views/admin/adminNotificationDeliveryView.js";
import { AdminApiTokensView } from "../views/admin/adminApiTokensView.js";
import { ProductsView } from "../views/products/productsView.js";
import { ProductComponentDiffView } from "../views/products/productComponentDiffView.js";
import { ProductDetailView } from "../views/products/productDetailView.js";
import { ControlsView } from "../views/controls/controlsView.js";
import { NotificationsView } from "../views/notifications/notificationsView.js";

export const ROUTES = [
  { path: "/login", view: LoginView, public: true },

  { path: "/", view: DashboardView, guard: () => requireAuth() },

  // Base list
  { path: "/vulnerabilities", view: VulnListView, guard: () => requireAuth() },

  { path: "/vulnerabilities/:id", view: VulnDetailView, guard: () => requireAuth() },

  // placeholders for later:
  { path: "/controls", view: ControlsView, guard: () => requireAuth() },
  { path: "/products", view: ProductsView, guard: () => requireAuth() },
  { path: "/products/component-diff", view: ProductComponentDiffView, guard: () => requireAuth() },
  { path: "/products/:id", view: ProductDetailView, guard: () => requireAuth() },
  { path: "/notifications", view: NotificationsView, guard: () => requireAuth() },

  { path: "/admin/users", view: AdminUsersView, guard: () => requireAuth() && requireRole("Admin") },
  { path: "/admin/logs", view: AdminLogsView, guard: () => requireAuth() && requireRole("Admin") },
  { path: "/admin/plugins", view: AdminPluginsView, guard: () => requireAuth() && requireRole("Admin") },
  { path: "/admin/notification-rules", view: AdminNotificationRulesView, guard: () => requireAuth() && requireRole("Admin") },
  { path: "/admin/notification-delivery", view: AdminNotificationDeliveryView, guard: () => requireAuth() && requireRole("Admin") },
  { path: "/admin/api-tokens", view: AdminApiTokensView, guard: () => requireAuth() },
];
