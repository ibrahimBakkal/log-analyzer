import { describe, expect, it } from "vitest";
import { type FollowedFile, INITIAL_LIVE, type LiveState, describeFile, fileName, liveReducer, liveSummary } from "./live";

function file(state: string, overrides: Partial<FollowedFile> = {}): FollowedFile {
  return { path: "/var/log/auth.log", state, detail: null, source: null, lines: 0, read_at: null, ...overrides };
}
const following = file("following", { source: "auth.log", lines: 1204 });
const count = (value: number) => new Intl.NumberFormat("tr-TR").format(value);

describe("liveReducer", () => {
  it("starts disconnected and following nothing", () => {
    expect(INITIAL_LIVE).toEqual({ connected: false, following: [], arrived: null });
  });

  it("tracks the connection", () => {
    const open = liveReducer(INITIAL_LIVE, { type: "open" });
    expect(open.connected).toBe(true);
    expect(liveReducer(open, { type: "lost" }).connected).toBe(false);
  });

  it("takes the followed files from a status event, which also proves the connection", () => {
    const state = liveReducer(INITIAL_LIVE, { type: "status", following: [following] });
    expect(state).toEqual({ connected: true, following: [following], arrived: null });
  });

  it("remembers the last batch of new events", () => {
    const state = liveReducer(INITIAL_LIVE, { type: "update", added: 5, at: 1000 });
    expect(state.arrived).toEqual({ added: 5, at: 1000 });
  });

  it("keeps the last arrival when an update adds nothing (a rule reload)", () => {
    const before: LiveState = { connected: true, following: [], arrived: { added: 5, at: 1000 } };
    expect(liveReducer(before, { type: "update", added: 0, at: 2000 }).arrived).toEqual({ added: 5, at: 1000 });
  });

  it("keeps what it knew about the files while the connection is lost", () => {
    const before: LiveState = { connected: true, following: [following], arrived: null };
    expect(liveReducer(before, { type: "lost" }).following).toEqual([following]);
  });
});

describe("liveSummary", () => {
  const state = (connected: boolean, ...files: FollowedFile[]): LiveState => ({ connected, following: files, arrived: null });

  it("says nothing when the server follows no file", () => {
    expect(liveSummary(state(true))).toBeNull();
    expect(liveSummary(state(false))).toBeNull();
  });

  it("is live as soon as one file is being followed", () => {
    expect(liveSummary(state(true, following))).toEqual({ tone: "live", text: "Canlı" });
    expect(liveSummary(state(true, file("waiting"), following, file("error")))?.tone).toBe("live");
  });

  it("says so when the connection is lost, whatever the files were doing", () => {
    expect(liveSummary(state(false, following))).toEqual({ tone: "off", text: "Bağlantı koptu" });
  });

  it("tells waiting for a file from not being able to read any", () => {
    expect(liveSummary(state(true, file("waiting")))).toEqual({ tone: "waiting", text: "Dosya bekleniyor" });
    expect(liveSummary(state(true, file("waiting"), file("error")))?.tone).toBe("waiting");
    expect(liveSummary(state(true, file("error"), file("error")))).toEqual({ tone: "problem", text: "İzlenemiyor" });
  });
});

describe("describeFile", () => {
  it("says how far a followed file has been read", () => {
    expect(describeFile(following, count)).toBe("izleniyor, 1.204 satır okundu");
  });

  it("says that a missing file is waited for", () => {
    expect(describeFile(file("waiting", { detail: "the file does not exist yet" }), count)).toBe("dosya henüz yok, bekleniyor");
  });

  it("passes on why a file cannot be read", () => {
    expect(describeFile(file("error", { detail: "Permission denied" }), count)).toBe("okunamıyor: Permission denied");
    expect(describeFile(file("error"), count)).toBe("okunamıyor");
  });

  it("falls back to the state's own name for one it does not know", () => {
    expect(describeFile(file("paused"), count)).toBe("paused");
  });
});

describe("fileName", () => {
  it("is the last part of a path", () => {
    expect(fileName("/var/log/auth.log")).toBe("auth.log");
    expect(fileName("C:\\logs\\ufw.log")).toBe("ufw.log");
    expect(fileName("auth.log")).toBe("auth.log");
    expect(fileName("/var/log/")).toBe("log");
  });
});
