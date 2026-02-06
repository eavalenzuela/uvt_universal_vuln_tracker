import { requireAuth, requireRole } from "./guards.js";
import { LoginView } from "../views/login/loginView.js";
import { DashboardView } from "../views/dashboard/dashboardView.js";
import { VulnListView } from "../views/vulnerabilities/vulnListView.js";
import { VulnDetailView } from "../views/vulnerabilities/vulnDetailView.js";
import { NotFoundView } from "../views/notFoundView.js";
import { AdminUsersView } from "../views/admin/adminUsersView.js";
import { AdminLogsView } from "../views/admin/adminLogsView.js";
import { AdminPluginsView } from "../views/admin/adminPluginsView.js";
import { AdminNotificationRulesView } from "../views/admin/adminNotificationRulesView.js";
import { ProductsView } from "../views/products/productsView.js";
import { ControlsView } from "../views/controls/controlsView.js";

export const ROUTES = [
  { path: "/login", view: LoginView, public: true },

  { path: "/", view: DashboardView, guard: () => requireAuth() },

  // Base list
  { path: "/vulnerabilities", view: VulnListView, guard: () => requireAuth() },

  { path: "/vulnerabilities/:id", view: VulnDetailView, guard: () => requireAuth() },

  // placeholders for later:
  { path: "/controls", view: ControlsView, guard: () => requireAuth() },
  { path: "/products", view: ProductsView, guard: () => requireAuth() },
  { path: "/products/:id", view: () => NotFoundView({ message: "Product detail not wired yet." }), guard: () => requireAuth() },

  { path: "/admin/users", view: AdminUsersView, guard: () => requireAuth() && requireRole("Admin") },
  { path: "/admin/logs", view: AdminLogsView, guard: () => requireAuth() && requireRole("Admin") },
  { path: "/admin/plugins", view: AdminPluginsView, guard: () => requireAuth() && requireRole("Admin") },
  { path: "/admin/notification-rules", view: AdminNotificationRulesView, guard: () => requireAuth() && requireRole("Admin") },
];
