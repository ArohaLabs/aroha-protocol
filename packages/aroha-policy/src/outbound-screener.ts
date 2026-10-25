// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Outbound PII screener (design spec §5).
 *
 * The mirror image of ContentScreener. That one asks "is this inbound text
 * trying to hijack my agent?" and blocks. This one asks "does this outbound
 * text carry an identifier that should not leave?" and redacts.
 *
 * Redaction rather than blocking is deliberate: a consult that fails because
 * it mentioned a phone number teaches the user to route around the screener,
 * whereas a consult that succeeds with the number replaced usually still gets
 * a useful answer. The screener should be invisible when it is right and
 * survivable when it is wrong.
 *
 * ── Scope: structured identifiers only ──────────────────────────────────────
 *
 * Emails, phone numbers, national IDs, card numbers, IPs, and API keys have
 * shapes. Names, addresses, and medical details do not, and a regex that
 * chases them produces false positives at a rate that makes the whole feature
 * annoying enough to disable. This screener does NOT redact names, and the
 * vectors say so explicitly so nobody later reads the omission as a bug.
 *
 * The real defence against unstructured leakage is the composer: the question
 * sent to a peer is CONSTRUCTED, never the user's raw conversation. This
 * screener is the second layer, for when the composer includes something it
 * shouldn't.
 *
 * ── Two properties worth knowing ────────────────────────────────────────────
 *
 * 1. Rule order is fixed and shared with the Python SDK. It matters: a card
 *    number contains substrings a loose phone rule would match, so cards run
 *    first and phones last. Reordering changes output for real inputs.
 *
 * 2. The result carries CATEGORIES and COUNTS, never matched values. The audit
 *    log records it verbatim (design spec §6.2) — if values could reach it,
 *    the audit trail would become the largest unredacted store of exactly the
 *    identifiers this screener exists to remove.
 */

export interface OutboundRule {
  /** Snake_case category name; uppercased in the placeholder. */
  category: string;
  /** Must carry the global flag — every occurrence is replaced, not just the first. */
  pattern: RegExp;
  /**
   * Optional second gate. A pattern can only describe a shape; a validator can
   * reject a match that has the right shape and the wrong meaning — a 16-digit
   * order number that is not a card number, say. Return false to leave the
   * match in place.
   */
  validate?: (match: string) => boolean;
}

export interface OutboundScreenerOptions {
  /** Extra rules, applied after the built-ins in the order given. */
  extraRules?: OutboundRule[];
  /** Replace the built-in rules entirely rather than extending them. */
  rules?: OutboundRule[];
}

export interface OutboundRedaction {
  category: string;
  count: number;
}

export interface OutboundScreenResult {
  /** The text with every matched identifier replaced. Safe to send. */
  text: string;
  /** What was removed, by category. Never contains a matched value. */
  redactions: OutboundRedaction[];
  /** True when at least one replacement happened. */
  redacted: boolean;
}

/**
 * Luhn checksum. Card numbers carry one; arbitrary long digit strings do not.
 * Without this check every 16-digit order number, tracking number, and account
 * reference in a question gets redacted, which is precisely the false-positive
 * rate that gets a screener switched off.
 */
export function passesLuhn(digits: string): boolean {
  if (!/^\d{13,19}$/.test(digits)) return false;

  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/**
 * Built-in rules, in application order.
 *
 * Order rationale, since it is load-bearing rather than incidental:
 *   email      — self-delimiting, cannot be confused with anything else
 *   api_key    — distinctive prefixes, no overlap with numeric rules
 *   ssn        — 3-2-4 digits; must precede any looser numeric rule
 *   credit_card— 13-19 digits; contains substrings the phone rule would match
 *   ip_address — dotted quads; must precede phone, which accepts "." separators
 *   phone      — the loosest numeric rule, so it runs last on what remains
 */
export const DEFAULT_OUTBOUND_RULES: OutboundRule[] = [
  {
    category: "email",
    pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
  },
  {
    category: "api_key",
    // Prefixed secrets from the providers an agent is most likely to hold.
    pattern: /\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})/g,
  },
  {
    category: "ssn",
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    category: "credit_card",
    pattern: /\b\d(?:[ -]?\d){12,18}\b/g,
    validate: (match) => passesLuhn(match.replace(/[ -]/g, "")),
  },
  {
    category: "ip_address",
    // Octet-bounded, so 999.1.1.1 is not treated as an address. A four-part
    // version string still matches; that false positive is accepted and
    // pinned by a vector rather than left to be rediscovered as a surprise.
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
  },
  {
    category: "phone",
    // International first: the domestic pattern would otherwise match the tail
    // of an international number and leave the country code stranded.
    pattern: /\+\d{1,3}[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
  },
  {
    category: "phone",
    // A separator is required. A bare run of ten digits is far more often an
    // order or account number than a phone number.
    pattern: /\(?\b\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g,
  },
];

function placeholder(category: string): string {
  return `[REDACTED:${category.toUpperCase()}]`;
}

export class OutboundScreener {
  private readonly rules: OutboundRule[];

  constructor(opts: OutboundScreenerOptions = {}) {
    this.rules = opts.rules
      ? [...opts.rules]
      : [...DEFAULT_OUTBOUND_RULES, ...(opts.extraRules ?? [])];
  }

  screen(text: string): OutboundScreenResult {
    const counts = new Map<string, number>();
    let out = text;

    for (const rule of this.rules) {
      // A fresh RegExp per pass: the shared /g patterns carry lastIndex, and
      // reusing one across calls makes results depend on call history.
      const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);

      out = out.replace(pattern, (match) => {
        if (rule.validate && !rule.validate(match)) return match;
        counts.set(rule.category, (counts.get(rule.category) ?? 0) + 1);
        return placeholder(rule.category);
      });
    }

    const redactions = [...counts.entries()]
      .map(([category, count]) => ({ category, count }))
      .sort((a, b) => a.category.localeCompare(b.category));

    return { text: out, redactions, redacted: redactions.length > 0 };
  }
}

/** Create an OutboundScreener with the default rules. */
export function createOutboundScreener(
  opts: OutboundScreenerOptions = {},
): OutboundScreener {
  return new OutboundScreener(opts);
}
