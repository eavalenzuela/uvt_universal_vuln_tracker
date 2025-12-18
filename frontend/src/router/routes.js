import { requireAuth, requireRole } from "./guards.js";
import { LoginView } from "../views/login/loginView.js";
import { DashboardView } from "../views/dashboard/dashboardView.js";
import { VulnListView } from "../views/vulnerabilities/vulnListView.js";
import { NotFoundView } from "../views/notFoundView.js";

// Later you can add: VulnDetailView for "/vulnerabilities/:id"
export const ROUTES = [
  { path: "/login", view: LoginView, public: true },

  { path: "/", view: DashboardView, guard: () => requireAuth() },

  // Base list
  { path: "/vulnerabilities", view: VulnListView, guard: () => requireAuth() },

  // Example placeholder detail route (safe even if you don’t implement yet)
  { path: "/vulnerabilities/:id", view: VulnListView, guard: () => requireAuth() },

  // placeholders for later:
  { path: "/products", view: () => NotFoundView({ message: "Products view not wired yet." }), guard: () => requireAuth() },
  { path: "/products/:id", view: () => NotFoundView({ message: "Product detail not wired yet." }), guard: () => requireAuth() },

  { path: "/admin/users", view: () => NotFoundView({ message: "Users admin view not wired yet." }), guard: () => requireAuth() && requireRole("Admin") },
];
