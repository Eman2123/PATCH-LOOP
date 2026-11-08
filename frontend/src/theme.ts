import { useSyncExternalStore } from "react";

export type Theme = "dark" | "light";
const KEY = "patchloop_theme";

export function getTheme(): Theme {
  return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
}

export function applyTheme(t: Theme) {
  const root = document.documentElement;
  root.setAttribute("data-theme", t);
  root.style.colorScheme = t;
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", t === "light" ? "#ECEEEF" : "#0d1117");
  window.dispatchEvent(new Event("themechange"));
}

export function setTheme(t: Theme) {
  try { localStorage.setItem(KEY, t); } catch { /* storage blocked */ }
  applyTheme(t);
}

export function useTheme(): Theme {
  return useSyncExternalStore(
    (cb) => { window.addEventListener("themechange", cb); return () => window.removeEventListener("themechange", cb); },
    getTheme,
    () => "dark" as Theme,
  );
}

/** Recharts needs concrete colours, so these mirror the CSS tokens in styles.css. */
export const chartColors = (t: Theme) =>
  t === "light"
    ? { grid: "#D6DCDF", axis: "#5a6b74", tipBg: "#F7F8F8", tipLine: "#C3CBCF", asr: "#c2453b", util: "#1d8660" }
    : { grid: "#262d38", axis: "#8b98a9", tipBg: "#161b22", tipLine: "#262d38", asr: "#ef7468", util: "#3fb68b" };
