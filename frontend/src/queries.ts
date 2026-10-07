// Server state: every read and write of the API goes through TanStack Query.

import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type QueryParams, api } from "./api";

const PAGE_SIZE = 200;

export function useStats(params: QueryParams = {}) {
  return useQuery({ queryKey: ["stats", params], queryFn: () => api.stats(params) });
}

export function useAlerts(params: QueryParams = {}) {
  return useQuery({
    queryKey: ["alerts", params],
    queryFn: () => api.alerts({ limit: 500, ...params }),
  });
}

export function useTimeline(params: QueryParams, enabled = true) {
  return useQuery({
    queryKey: ["timeline", params],
    queryFn: () => api.timeline(params),
    enabled,
    // Keep the previous bars on screen while a new range loads.
    placeholderData: keepPreviousData,
  });
}

export function usePorts(params: QueryParams, enabled = true) {
  return useQuery({
    queryKey: ["ports", params],
    queryFn: () => api.ports(params),
    enabled,
    placeholderData: keepPreviousData,
  });
}

export function useEvents(params: QueryParams) {
  return useInfiniteQuery({
    queryKey: ["events", params],
    queryFn: ({ pageParam }) => api.events({ ...params, limit: PAGE_SIZE, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
  });
}

/** The followed files in detail. The event stream only says when their state changes. */
export function useFollow(enabled: boolean) {
  return useQuery({ queryKey: ["follow"], queryFn: api.follow, enabled });
}

export function useRules() {
  return useQuery({ queryKey: ["rules"], queryFn: api.rules });
}

/** Uploading a log or reloading the rules changes events and alerts: refetch everything. */
export function useReloadRules() {
  const client = useQueryClient();
  return useMutation({ mutationFn: api.reloadRules, onSuccess: () => client.invalidateQueries() });
}

export function useIngest() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ file, year, tz }: { file: File; year?: string; tz?: string }) => api.ingest(file, { year, tz }),
    onSuccess: () => client.invalidateQueries(),
  });
}
