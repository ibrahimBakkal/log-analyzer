import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, HashRouter, MemoryRouter, Route, Routes } from "react-router";
import { DEMO } from "./api";
import { Layout, Notice, Panel } from "./components/Layout";
import "./index.css";
import { Dashboard } from "./pages/Dashboard";
import { Investigate } from "./pages/Investigate";
import { Rules } from "./pages/Rules";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 10_000, retry: 1, refetchOnWindowFocus: false },
  },
});

/**
 * Where the page keeps its place. A server can answer /inceleme with the app;
 * the demo is a single file, so it keeps the place after the # instead, and
 * where the address cannot be changed at all (some embedding frames) in memory.
 */
function pickRouter() {
  if (!DEMO) return BrowserRouter;
  try {
    window.history.replaceState(window.history.state, "", window.location.hash || "#/");
    return HashRouter;
  } catch {
    return MemoryRouter;
  }
}
const Router = pickRouter();

function NotFound() {
  return (
    <Panel>
      <Notice>Böyle bir sayfa yok. Üstteki bağlantılardan birini seç.</Notice>
    </Panel>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <Router>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="inceleme" element={<Investigate />} />
            <Route path="kurallar" element={<Rules />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </Router>
    </QueryClientProvider>
  </StrictMode>,
);
