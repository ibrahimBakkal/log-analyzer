import { useState } from "react";
import { NavLink, Outlet } from "react-router";

const PAGES = [
  { to: "/", label: "Özet" },
  { to: "/inceleme", label: "İnceleme" },
  { to: "/kurallar", label: "Kurallar" },
];

function ThemeToggle() {
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme ?? "light");
  const next = theme === "dark" ? "light" : "dark";

  function toggle() {
    document.documentElement.dataset.theme = next;
    setTheme(next);
    try {
      localStorage.setItem("theme", next);
    } catch {
      // Storage can be unavailable (private window); the choice then lasts for this visit.
    }
  }

  return (
    <button type="button" className="button" onClick={toggle} aria-label={`${next === "dark" ? "Koyu" : "Açık"} temaya geç`}>
      <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true">
        {theme === "dark" ? (
          <path d="M8 1v2M8 13v2M1 8h2M13 8h2M3 3l1.4 1.4M11.6 11.6L13 13M3 13l1.4-1.4M11.6 4.4L13 3M8 5a3 3 0 1 0 0 6a3 3 0 0 0 0-6Z" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
        ) : (
          <path d="M13.5 9.5A6 6 0 0 1 6.5 2.5a6 6 0 1 0 7 7Z" fill="currentColor" />
        )}
      </svg>
      <span className="hidden sm:inline">{next === "dark" ? "Koyu" : "Açık"}</span>
    </button>
  );
}

export function Layout() {
  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-20 border-b border-rule bg-surface">
        <div className="mx-auto flex h-12 max-w-[1680px] items-center gap-2 px-4 sm:gap-6">
          <span className="hidden font-mono text-[15px] font-bold tracking-tight min-[480px]:inline">log-analyzer</span>
          <nav className="flex h-full items-stretch gap-1" aria-label="Sayfalar">
            {PAGES.map((page) => (
              <NavLink
                key={page.to}
                to={page.to}
                end={page.to === "/"}
                className={({ isActive }) =>
                  `flex items-center border-b-2 px-3 font-semibold ${
                    isActive ? "border-accent text-accent" : "border-transparent text-ink-2 hover:text-ink"
                  }`
                }
              >
                {page.label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto">
            <ThemeToggle />
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-[1680px] px-4 py-4">
        <Outlet />
      </main>
    </div>
  );
}

/** A plain titled region: the interface is built from these rather than from cards. */
export function Panel({ title, aside, children, className = "" }: { title?: string; aside?: React.ReactNode; children: React.ReactNode; className?: string }) {
  return (
    <section className={`rounded-md border border-rule bg-surface ${className}`}>
      {title && (
        <div className="flex min-h-10 items-center justify-between gap-3 border-b border-rule px-3 py-1.5">
          <h2 className="text-[15px] font-bold">{title}</h2>
          {aside}
        </div>
      )}
      {children}
    </section>
  );
}

export function Notice({ tone = "info", children }: { tone?: "info" | "error"; children: React.ReactNode }) {
  return (
    <p
      role={tone === "error" ? "alert" : undefined}
      className={`m-0 px-3 py-6 text-center ${tone === "error" ? "text-[var(--sev-critical)]" : "text-ink-2"}`}
    >
      {children}
    </p>
  );
}
