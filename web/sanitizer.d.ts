export type FindingDisposition = "actionable" | "contextual" | "informational";

export interface UnicodeFinding {
  index: number;
  utf16Index: number;
  byteOffset: number;
  codepoint: string;
  category: string;
  label: string;
  disposition: FindingDisposition;
  context: string;
  safeAction: "delete" | "space" | "preserve";
}

export interface UnicodeEdit {
  index: number;
  byteOffset: number;
  codepoint: string;
  category: string;
  action: "delete" | "space" | "replace" | "insert";
  original: string;
  replacement: string;
  disposition: FindingDisposition;
  context: string;
  stage: "policy" | "normalization";
}

export interface SanitizeReport {
  cleanedText: string;
  changed: boolean;
  counts: Readonly<Record<string, number>>;
  edits: readonly UnicodeEdit[];
  policyVersion: string;
}

/** Inspect suspicious Unicode locally without changing the input. */
export function inspectText(text: string): UnicodeFinding[];

/** Apply the context-aware safe profile and return only cleaned text. */
export function sanitizeText(text: string): string;

/** Apply the safe profile and return a local, auditable edit report. */
export function sanitizeTextWithReport(text: string): SanitizeReport;
