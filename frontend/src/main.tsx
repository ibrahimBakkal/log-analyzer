import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router";
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
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="inceleme" element={<Investigate />} />
            <Route path="kurallar" element={<Rules />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
