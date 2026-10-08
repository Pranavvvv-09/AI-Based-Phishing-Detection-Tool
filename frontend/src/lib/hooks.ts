import { type RefObject, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { Filter } from "../components/StatusFilter";
import type { Toast } from "../components/Toasts";
import type { RangeDays } from "./api";
import { motionMs } from "./motion";

/**
 * One choice kept in the URL (?name=value), so it survives a reload and the back button.
 * The default value is left out of the URL.
 */
function useUrlChoice<T extends string>(name: string, options: readonly T[], fallback: T): [T, (value: T) => void] {
  const read = useCallback(() => {
    const value = new URLSearchParams(window.location.search).get(name) as T | null;
    return value && options.includes(value) ? value : fallback;
  }, [name, options, fallback]);
  const [choice, setChoice] = useState<T>(read);

  useEffect(() => {
    const onPop = () => setChoice(read());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, [read]);

  const update = useCallback(
    (value: T) => {
      const url = new URL(window.location.href);
      if (value === fallback) url.searchParams.delete(name);
      else url.searchParams.set(name, value);
      window.history.pushState(null, "", url);
      setChoice(value);
    },
    [name, fallback],
  );

  return [choice, update];
}

const FILTERS: readonly Filter[] = ["held", "restored", "all"];

/** The status filter lives in the URL (?status=restored). */
export function useStatusFilter(): [Filter, (value: Filter) => void] {
  return useUrlChoice("status", FILTERS, "held");
}

const RANGES = ["7d", "30d", "90d"] as const;

/** The overview's time range lives in the URL (?range=7d); 30 days by default. */
export function useRange(): [RangeDays, (days: RangeDays) => void] {
  const [range, setRange] = useUrlChoice("range", RANGES, "30d");
  const update = useCallback((days: RangeDays) => setRange(`${days}d`), [setRange]);
  return [Number.parseInt(range, 10) as RangeDays, update];
}

/** The rendered width of an element, kept current with ResizeObserver (0 until known). */
export function useWidth<T extends HTMLElement>(): [RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    setWidth(element.clientWidth);
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(([entry]) => setWidth(Math.round(entry.contentRect.width)));
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  return [ref, width];
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
  // Dismissing marks the toast as leaving (it plays the close transition), then removes it.
  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.map((toast) => (toast.id === id ? { ...toast, leaving: true } : toast)));
    window.setTimeout(
      () => setToasts((current) => current.filter((toast) => toast.id !== id)),
      motionMs("--toast-close", 160),
    );
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

/**
 * Scroll-spy for in-page sections: which one the reader is in. ``goTo`` marks a section
 * current straight away (the nav pill slides at once) and holds the spy while the page
 * glides there, so the pill doesn't stop at every section on the way.
 */
export function useActiveSection<T extends string>(ids: readonly T[]): [T, (id: T) => void] {
  const [active, setActive] = useState<T>(ids[0]);
  const lockUntil = useRef(0);

  const measure = useCallback(() => {
    if (Date.now() < lockUntil.current) return;
    let current = ids[0];
    for (const id of ids) {
      const element = document.getElementById(id);
      if (element && element.getBoundingClientRect().top <= 140) current = id;
    }
    // Scrolled to the very end: the last section is current even if it is short.
    const end = document.documentElement.scrollHeight - 2;
    if (window.scrollY > 0 && window.innerHeight + window.scrollY >= end) current = ids[ids.length - 1];
    setActive(current);
  }, [ids]);

  useEffect(() => {
    let frame = 0;
    const onScroll = () => {
      if (!frame) frame = requestAnimationFrame(() => ((frame = 0), measure()));
    };
    measure();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
    };
  }, [measure]);

  const goTo = useCallback(
    (id: T) => {
      setActive(id);
      lockUntil.current = Date.now() + 900;
      window.setTimeout(measure, 950);
    },
    [measure],
  );

  return [active, goTo];
}

/**
 * transitions.dev "tabs sliding", moved by transform only: the pill is translated to the
 * active tab (and on a horizontal bar scaled to its width), never resized through layout.
 * First paint and resizes place it without a transition, so it never animates in from 0.
 */
export function useSlidingPill<T extends HTMLElement = HTMLElement>(active: string, axis: "x" | "y") {
  const bar = useRef<T>(null);
  const pill = useRef<HTMLSpanElement>(null);
  const placed = useRef(false);

  const place = useCallback(
    (animate: boolean) => {
      const tab = bar.current?.querySelector<HTMLElement>(`[data-tab="${active}"]`);
      const marker = pill.current;
      if (!tab || !marker) return;
      const transform =
        axis === "y"
          ? `translateY(${tab.offsetTop}px)`
          : `translateX(${tab.offsetLeft}px) scaleX(${tab.offsetWidth / (marker.offsetWidth || 1)})`;
      if (animate) {
        marker.style.transform = transform;
        return;
      }
      const previous = marker.style.transition;
      marker.style.transition = "none";
      marker.style.transform = transform;
      void marker.offsetWidth; // reflow before restoring the transition
      marker.style.transition = previous;
    },
    [active, axis],
  );

  useLayoutEffect(() => {
    place(placed.current);
    placed.current = true;
  }, [place]);

  useEffect(() => {
    const element = bar.current;
    if (!element || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(() => place(false)); // fonts loading, window resizes
    observer.observe(element);
    return () => observer.disconnect();
  }, [place]);

  return { bar, pill };
}
