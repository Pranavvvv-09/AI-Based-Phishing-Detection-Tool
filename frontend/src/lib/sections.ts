// The dashboard's in-page sections, in page order (ids of their elements).
export const SECTIONS = ["overview", "quarantine", "quick-scan"] as const;
export type Section = (typeof SECTIONS)[number];
