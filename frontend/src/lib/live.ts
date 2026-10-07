// What the page knows about the server's live side: the event stream and the files it follows.

import type { FollowedFile } from "../api";

export type { FollowedFile };

export interface LiveState {
  /** The event stream is open: changes on the server arrive by themselves. */
  connected: boolean;
  following: FollowedFile[];
  /** The last batch of new events, for showing that something just came in. */
  arrived: { added: number; at: number } | null;
}

export const INITIAL_LIVE: LiveState = { connected: false, following: [], arrived: null };

export type LiveAction =
  | { type: "open" }
  | { type: "lost" }
  | { type: "status"; following: FollowedFile[] }
  | { type: "update"; added: number; at: number };

export function liveReducer(state: LiveState, action: LiveAction): LiveState {
  switch (action.type) {
    case "open":
      return { ...state, connected: true };
    case "lost":
      return { ...state, connected: false };
    case "status":
      return { ...state, connected: true, following: action.following };
    case "update":
      return { ...state, connected: true, arrived: action.added > 0 ? { added: action.added, at: action.at } : state.arrived };
  }
}

export type LiveTone = "live" | "waiting" | "problem" | "off";

/**
 * What the header says about live following, or null if there is nothing to say:
 * a server that follows no file gives the page nothing to be "live" about.
 */
export function liveSummary(state: LiveState): { tone: LiveTone; text: string } | null {
  if (state.following.length === 0) return null;
  if (!state.connected) return { tone: "off", text: "Bağlantı koptu" };
  if (state.following.some((file) => file.state === "following")) return { tone: "live", text: "Canlı" };
  if (state.following.every((file) => file.state === "error")) return { tone: "problem", text: "İzlenemiyor" };
  return { tone: "waiting", text: "Dosya bekleniyor" };
}

const STATE_TEXT: Record<string, string> = {
  following: "izleniyor",
  waiting: "dosya henüz yok, bekleniyor",
  error: "okunamıyor",
};

/** One followed file in words: "izleniyor, 1.204 satır okundu". */
export function describeFile(file: FollowedFile, formatCount: (value: number) => string): string {
  const state = STATE_TEXT[file.state] ?? file.state;
  if (file.state === "following") return `${state}, ${formatCount(file.lines)} satır okundu`;
  return file.detail && file.state === "error" ? `${state}: ${file.detail}` : state;
}

/** The last part of a path, whichever way its slashes lean. */
export function fileName(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}
