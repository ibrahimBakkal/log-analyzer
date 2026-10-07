// The page's connection to the server's event stream (GET /stream).

import { useQueryClient } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useReducer } from "react";
import { API_URL, DEMO } from "./api";
import { INITIAL_LIVE, type LiveState, liveReducer } from "./lib/live";

const LiveContext = createContext<LiveState>(INITIAL_LIVE);

/** What the server is following and whether its changes reach this page by themselves. */
export function useLive(): LiveState {
  return useContext(LiveContext);
}

const RECONNECT_MS = 5000;

/**
 * Listens to the server for as long as the page is open. When the server says
 * that events or alerts have changed, everything on screen is fetched again; the
 * stream itself carries no data. The demo has no server and listens to nothing.
 */
export function LiveProvider({ children }: { children: React.ReactNode }) {
  const client = useQueryClient();
  const [state, dispatch] = useReducer(liveReducer, INITIAL_LIVE);

  useEffect(() => {
    if (DEMO || typeof EventSource === "undefined") return;
    let source: EventSource | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let wasLost = false;

    function connect() {
      source = new EventSource(`${API_URL}/stream`);
      source.onopen = () => {
        // Whatever happened while the stream was down went unannounced.
        if (wasLost) void client.invalidateQueries();
        wasLost = false;
        dispatch({ type: "open" });
      };
      source.onerror = () => {
        wasLost = true;
        dispatch({ type: "lost" });
        // The browser reconnects by itself unless it has given up on the address.
        if (source?.readyState === EventSource.CLOSED) {
          source.close();
          retry = setTimeout(connect, RECONNECT_MS);
        }
      };
      source.addEventListener("status", (event) => {
        dispatch({ type: "status", following: JSON.parse((event as MessageEvent<string>).data).following });
      });
      source.addEventListener("update", (event) => {
        const update = JSON.parse((event as MessageEvent<string>).data) as { added: number };
        dispatch({ type: "update", added: update.added, at: Date.now() });
        void client.invalidateQueries();
      });
    }

    connect();
    return () => {
      clearTimeout(retry);
      source?.close();
    };
  }, [client]);

  return <LiveContext.Provider value={state}>{children}</LiveContext.Provider>;
}
