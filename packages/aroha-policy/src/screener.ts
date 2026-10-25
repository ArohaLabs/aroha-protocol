// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Content screener for inbound RunRequest messages.
 *
 * Screens the `message` and `history` fields of a RunRequest for known
 * prompt-injection patterns. Intended for use as middleware in serve()
 * before the handler runs — the LLM never sees injected content that
 * triggers the screener.
 *
 * Pattern matching is deterministic and requires no LLM call.
 * For production deployments, combine with a classifier model for
 * higher recall on novel injections.
 */

// ── Default injection patterns ────────────────────────────────────────────────
//
// These cover the most common direct-injection vectors documented in
// OWASP Top 10 for Agentic Applications 2026 and the prompt-infection
// research (arXiv:2410.07283).  Extend with domain-specific patterns.

const DEFAULT_PATTERNS: RegExp[] = [
  // Instruction override attempts
  /ignore\s+(all\s+)?previous\s+instructions?/i,
  /disregard\s+(all\s+)?prior\s+(instructions?|context)/i,
  /forget\s+(everything|all)\s+(you('ve|\s+have)\s+)?(been\s+told|learned|seen)/i,
  /you\s+are\s+now\s+(a\s+)?(?:different|new|another)\s+(ai|assistant|model|system)/i,
  /new\s+system\s+prompt:/i,
  /\[SYSTEM\]/i,
  /\[INST\]/i,

  // Exfiltration / tool misuse
  /repeat\s+(everything|all|your\s+instructions?|the\s+system\s+prompt)\s+(back|above|verbatim)/i,
  /print\s+(your\s+)?system\s+prompt/i,
  /reveal\s+(your\s+)?(instructions?|system\s+prompt|configuration)/i,

  // Role-play jailbreaks
  /pretend\s+(you\s+are|to\s+be)\s+(dan|evil|jailbroken|unfiltered)/i,
  /act\s+as\s+(if\s+you\s+have\s+no\s+)?(restrictions?|guidelines?|limits?)/i,

  // Encoded injection markers
  /<\/?s?[Yy]stem>/,
  /<<<[A-Z_]+>>>/,
];

// ── Screener interface ────────────────────────────────────────────────────────

export interface ScreenerOptions {
  /** Additional regex patterns to detect. */
  extraPatterns?: RegExp[];
  /**
   * Maximum length of the message field in characters.
   * Overlong messages with trust:"untrusted" are flagged.
   * Default: 32_000
   */
  maxLength?: number;
  /**
   * Only screen content with this trust value.
   * Default: "untrusted" — trusted callers are not screened.
   */
  screenTrust?: "trusted" | "untrusted" | "both";
}

export interface ScreenResult {
  blocked:  boolean;
  reason?:  string;
  pattern?: string;
}

export class ContentScreener {
  private readonly patterns: RegExp[];
  private readonly maxLength: number;
  private readonly screenTrust: "trusted" | "untrusted" | "both";

  constructor(opts: ScreenerOptions = {}) {
    this.patterns    = [...DEFAULT_PATTERNS, ...(opts.extraPatterns ?? [])];
    this.maxLength   = opts.maxLength ?? 32_000;
    this.screenTrust = opts.screenTrust ?? "untrusted";
  }

  screen(message: string, trust: "trusted" | "untrusted" = "untrusted"): ScreenResult {
    if (this.screenTrust !== "both" && trust !== this.screenTrust) {
      return { blocked: false };
    }

    if (message.length > this.maxLength) {
      return {
        blocked: true,
        reason:  `Message length ${message.length} exceeds max ${this.maxLength} for untrusted content`,
      };
    }

    for (const pattern of this.patterns) {
      if (pattern.test(message)) {
        return {
          blocked: true,
          reason:  "Potential prompt injection pattern detected in untrusted content",
          pattern: pattern.toString(),
        };
      }
    }

    return { blocked: false };
  }

  screenHistory(
    history: Array<{ role: string; content: string }>,
    trust: "trusted" | "untrusted" = "untrusted",
  ): ScreenResult {
    for (const msg of history) {
      if (msg.role === "user" || msg.role === "tool") {
        const result = this.screen(msg.content, trust);
        if (result.blocked) return result;
      }
    }
    return { blocked: false };
  }
}

/**
 * Create a ContentScreener with the default patterns.
 * Pass extraPatterns to extend for domain-specific injection vectors.
 */
export function createContentScreener(opts: ScreenerOptions = {}): ContentScreener {
  return new ContentScreener(opts);
}
