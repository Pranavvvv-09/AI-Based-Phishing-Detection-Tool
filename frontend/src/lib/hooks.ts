import { useCallback, useEffect, useState } from "react";
import type { Filter } from "../components/StatusFilter";
import type { Toast } from "../components/Toasts";

const FILTERS: Filter[] = ["held", "restored", "all"];

/** The status filter lives in the URL (?status=restored), so it survives a reload. */
export function useStatusFilter(): [Filter, (value: Filter) => void] {
  const read = () => {
    const value = new URLSearchParams(window.location.search).get("status") as Filter | null;
    return value && FILTERS.includes(value) ? value : "held";
  };
  const [filter, setFilter] = useState<Filter>(read);

  useEffect(() => {
    const onPop = () => setFilter(read());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const update = useCallback((value: Filter) => {
    const url = new URL(window.location.href);
    if (value === "held") url.searchParams.delete("status");
    else url.searchParams.set("status", value);
    window.history.pushState(null, "", url);
    setFilter(value);
  }, []);

  return [filter, update];
}

/** Current time, refreshed every minute, so "3 minutes ago" stays true. */
export function useNow(intervalMs = 60_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs]);
  return now;
}

let nextToastId = 1;

export function useToasts(timeoutMs = 6000) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);
  const push = useCallback(
    (toast: Omit<Toast, "id">) => {
      const id = nextToastId++;
      setToasts((current) => [...current.slice(-3), { ...toast, id }]);
      window.setTimeout(() => dismiss(id), timeoutMs);
    },
    [dismiss, timeoutMs],
  );
  return { toasts, push, dismiss };
}
