import { ROUTES } from "./routes.js";
import { renderShell } from "../ui/layout/shell.js";
import { toast } from "../ui/components/toast.js";
import { closeNotificationDropdown } from "../ui/layout/header.js";

let _currentPath = "/";
let _currentParams = {};

export function currentPath() {
  return _currentPath;
}

export function currentParams() {
  return _currentParams;
}

function getHashPath() {
  const raw = window.location.hash || "";
  const h = raw.startsWith("#") ? raw.slice(1) : raw;
  const path = h.startsWith("/") ? h : `/${h}`;
  return path === "/" ? "/" : path;
}

export function navigate(path) {
  if (!path.startsWith("/")) path = `/${path}`;
  window.location.hash = path;
}

function splitPath(p) {
  return (p || "/")
    .split("?")[0]
    .split("#")[0]
    .split("/")
    .filter(Boolean);
}

function matchPattern(pattern, actual) {
  // pattern: "/vulnerabilities/:id"
  // actual:  "/vulnerabilities/123"
  const pSeg = splitPath(pattern);
  const aSeg = splitPath(actual);

  if (pSeg.length !== aSeg.length) return null;

  const params = {};
  for (let i = 0; i < pSeg.length; i++) {
    const p = pSeg[i];
    const a = aSeg[i];

    if (p.startsWith(":")) {
      params[p.slice(1)] = decodeURIComponent(a);
      continue;
    }
    if (p !== a) return null;
  }
  return params;
}

function matchRoute(pathname) {
  // exact match first
  const exact = ROUTES.find(r => r.path === pathname);
  if (exact) return { route: exact, params: {} };

  // pattern match
  for (const r of ROUTES) {
    if (!r.path.includes(":")) continue;
    const params = matchPattern(r.path, pathname);
    if (params) return { route: r, params };
  }

  return null;
}

export async function route() {
  _currentPath = getHashPath();
  _currentParams = {};
  closeNotificationDropdown();

  const matched = matchRoute(_currentPath);
  const main = document.getElementById("app-main");
  if (!main) return;

  renderShell();

  if (!matched) {
    main.innerHTML = "";
    const { NotFoundView } = await import("../views/notFoundView.js");
    main.appendChild(NotFoundView({}));
    return;
  }

  const { route: routeDef, params } = matched;
  _currentParams = params;

  if (routeDef.guard && !routeDef.guard()) {
    toast({ title: "Access denied", message: "Please log in (or you lack permission)." });
    navigate("/login");
    return;
  }

  main.innerHTML = "";
  // If you want views to receive params, you can call: routeDef.view(params)
  const node = await routeDef.view(params);
  if (node) main.appendChild(node);

  main.focus();
}

export function startRouter() {
  window.addEventListener("hashchange", () => route());

  if (!window.location.hash) {
    window.location.hash = "/";
  } else {
    route();
  }
}
