#!/usr/bin/env node
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Spec parity check. The ReSpec HTML specifications are hand-authored; their
// Markdown counterparts are the source of truth. This script fails when the
// HTML is missing normative content that the Markdown has, or when the two
// published copies of the HTML have drifted apart.
//
// Checks, per Markdown/HTML pair in spec-public/spec:
//   1. Every Markdown heading (level 2 and below) appears in an HTML heading
//      (section numbers stripped; the Markdown heading text must occur, on
//      word boundaries, within some HTML heading).
//   2. Every Markdown sentence containing an RFC 2119 keyword (MUST, MUST NOT,
//      SHOULD, SHOULD NOT, MAY, REQUIRED, SHALL, RECOMMENDED, OPTIONAL) occurs
//      in the HTML text, after both sides are normalised (markup stripped,
//      entities decoded, case folded, punctuation and whitespace collapsed).
//   3. Structure: the HTML has balanced tags and no duplicate id attributes.
// And across copies:
//   4. docs/spec/*.html is byte-for-byte identical to spec-public/spec/*.html.
//
// No dependencies. Usage: node scripts/check-spec-parity.mjs

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SOURCE_DIR = join(ROOT, "spec-public", "spec");
const MIRROR_DIR = join(ROOT, "docs", "spec");

const PAIRS = [
  { md: "aroha-1.0.md", html: "aroha-1.0.html" },
  { md: "did-method.md", html: "did-aroha-method-1.0.html" },
];

// Markdown headings that are document metadata rather than sections. ReSpec
// renders these from <title> / respecConfig, not from a heading element.
const IGNORED_HEADINGS = new Set([
  "specification version 1 0", // aroha-1.0.md subtitle; the HTML <title> carries the version
]);

// ReSpec generates the heading for these well-known section ids.
const RESPEC_SECTION_HEADINGS = {
  abstract: "Abstract",
  sotd: "Status of This Document",
  conformance: "Conformance",
  references: "References",
};

const RFC2119 = /\b(MUST|SHOULD|MAY|REQUIRED|SHALL|RECOMMENDED|OPTIONAL)\b/;

const VOID_ELEMENTS = new Set([
  "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
  "source", "track", "wbr",
]);

const ENTITIES = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", mdash: "—",
  ndash: "–", rarr: "→", larr: "←", hellip: "…", sect: "§", times: "×",
  ge: "≥", le: "≤", rsquo: "’", lsquo: "‘", rdquo: "”", ldquo: "“", copy: "©",
};

function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, (m, e) => {
    if (e[0] === "#") {
      const cp = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(cp) ? String.fromCodePoint(cp) : m;
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

/** Case-fold and reduce to space-separated alphanumeric words. */
function normalise(s) {
  return ` ${s
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim()} `;
}

function stripInlineMarkdown(s) {
  return s
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/<[^>]+>/g, " ")
    .replace(/\\\|/g, "|")
    .replace(/`/g, "")
    .replace(/\*\*|__/g, "")
    .replace(/(^|[\s(])\*(\S)/g, "$1$2")
    .replace(/(\S)\*(?=[\s).,;:]|$)/g, "$1");
}

function splitSentences(text) {
  return text
    .split(/(?<=[.!?:])\s+(?=[A-Z0-9"'(\[])/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Parse Markdown into headings and text blocks (paragraphs, list items, table cells). */
function parseMarkdown(src) {
  const lines = src.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, "")).split(/\r?\n/);
  const headings = [];
  const blocks = [];
  let current = null;
  let inFence = false;

  const flush = () => {
    if (current && current.text.trim()) blocks.push(current);
    current = null;
  };

  lines.forEach((raw, i) => {
    const lineNo = i + 1;
    if (/^\s*(```|~~~)/.test(raw)) {
      flush();
      inFence = !inFence;
      return;
    }
    if (inFence) return;

    const heading = raw.match(/^(#{1,6})\s+(.*?)\s*#*\s*$/);
    if (heading) {
      flush();
      if (heading[1].length >= 2) headings.push({ text: stripInlineMarkdown(heading[2]).trim(), line: lineNo });
      return;
    }
    if (/^\s*$/.test(raw) || /^\s*(-{3,}|\*{3,})\s*$/.test(raw)) {
      flush();
      return;
    }
    if (/^!!!/.test(raw)) {
      flush();
      return;
    }

    let line = raw.replace(/^\s*>\s?/, "");
    if (/^\s*\|/.test(line)) {
      flush();
      if (/^\s*\|[\s:|-]+\|?\s*$/.test(line)) return; // separator row
      const cells = line
        .trim()
        .replace(/^\|/, "")
        .replace(/\|$/, "")
        .split(/(?<!\\)\|/);
      for (const cell of cells) if (cell.trim()) blocks.push({ text: cell.trim(), line: lineNo });
      return;
    }
    const item = line.match(/^\s*(?:[-*+]|\d+\.)\s+(.*)$/);
    if (item) {
      flush();
      current = { text: item[1], line: lineNo };
      return;
    }
    if (!current) current = { text: line.trim(), line: lineNo };
    else current.text += " " + line.trim();
  });
  flush();
  return { headings, blocks };
}

function stripNumbering(heading) {
  return heading
    .replace(/^\s*(?:§\s*)?(?:[A-Z]\.)?\d+(?:\.\d+)*[a-z]?\.?\s+/, "")
    .trim();
}

function parseHtml(src) {
  const cleaned = src
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<script\b[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[\s\S]*?<\/style>/gi, " ");
  const toText = (s) => decodeEntities(s.replace(/<[^>]+>/g, " "));

  const headings = [];
  for (const m of cleaned.matchAll(/<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1>/gi)) headings.push(toText(m[2]));
  for (const m of cleaned.matchAll(/<section\b[^>]*\bid="([^"]+)"/gi)) {
    if (RESPEC_SECTION_HEADINGS[m[1]]) headings.push(RESPEC_SECTION_HEADINGS[m[1]]);
  }
  const title = src.match(/<title>([\s\S]*?)<\/title>/i);
  if (title) headings.push(toText(title[1]));
  return { headings, text: toText(cleaned) };
}

function checkStructure(src, label) {
  const problems = [];
  const lineOf = (idx) => src.slice(0, idx).split("\n").length;

  const ids = new Map();
  for (const m of src.matchAll(/\sid="([^"]*)"/g)) {
    if (ids.has(m[1])) problems.push(`${label}:${lineOf(m.index)} duplicate id "${m[1]}" (first at line ${ids.get(m[1])})`);
    else ids.set(m[1], lineOf(m.index));
  }

  // Blank out comments and raw-text elements, preserving offsets for line numbers.
  const blank = (m) => m.replace(/[^\n]/g, " ");
  const body = src
    .replace(/<!--[\s\S]*?-->/g, blank)
    .replace(/(<script\b[^>]*>)([\s\S]*?)(<\/script>)/gi, (m, a, b, c) => a + blank(b) + c)
    .replace(/(<style\b[^>]*>)([\s\S]*?)(<\/style>)/gi, (m, a, b, c) => a + blank(b) + c);
  const stack = [];
  let mismatched = false;
  for (const m of body.matchAll(/<(\/?)([a-zA-Z][a-zA-Z0-9-]*)\b[^>]*?(\/?)>/g)) {
    const [, closing, rawName, selfClosing] = m;
    const name = rawName.toLowerCase();
    if (name === "!doctype") continue;
    if (VOID_ELEMENTS.has(name) || selfClosing) continue;
    if (!closing) {
      stack.push({ name, line: lineOf(m.index) });
      continue;
    }
    const top = stack.pop();
    if (!top) {
      problems.push(`${label}:${lineOf(m.index)} unexpected </${name}>`);
    } else if (top.name !== name) {
      problems.push(`${label}:${lineOf(m.index)} </${name}> closes <${top.name}> opened at line ${top.line}`);
      mismatched = true;
      break; // later errors would cascade
    }
  }
  if (!mismatched) for (const open of stack) problems.push(`${label}:${open.line} <${open.name}> is never closed`);
  return problems;
}

function checkPair({ md, html }) {
  const mdPath = join(SOURCE_DIR, md);
  const htmlPath = join(SOURCE_DIR, html);
  const problems = [];
  if (!existsSync(mdPath) || !existsSync(htmlPath)) {
    return { problems: [`missing file: ${existsSync(mdPath) ? htmlPath : mdPath}`], stats: "" };
  }
  const mdDoc = parseMarkdown(readFileSync(mdPath, "utf8"));
  const htmlSrc = readFileSync(htmlPath, "utf8");
  const htmlDoc = parseHtml(htmlSrc);
  const htmlText = normalise(htmlDoc.text);
  const htmlHeadings = htmlDoc.headings.map((h) => normalise(stripNumbering(h)));

  let headingCount = 0;
  for (const h of mdDoc.headings) {
    const n = normalise(stripNumbering(h.text));
    if (IGNORED_HEADINGS.has(n.trim())) continue;
    headingCount++;
    if (!htmlHeadings.some((hh) => hh.includes(n))) {
      problems.push(`${md}:${h.line} heading missing from ${html}: "${h.text}"`);
    }
  }

  let sentenceCount = 0;
  for (const block of mdDoc.blocks) {
    for (const sentence of splitSentences(stripInlineMarkdown(block.text))) {
      if (!RFC2119.test(sentence)) continue;
      sentenceCount++;
      if (!htmlText.includes(normalise(sentence))) {
        problems.push(`${md}:${block.line} normative sentence missing from ${html}:\n      "${sentence}"`);
      }
    }
  }

  problems.push(...checkStructure(htmlSrc, `spec-public/spec/${html}`));
  return { problems, stats: `${headingCount} headings, ${sentenceCount} normative sentences` };
}

function checkMirror() {
  const problems = [];
  const htmlIn = (dir) => (existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith(".html")) : []);
  const source = htmlIn(SOURCE_DIR);
  const mirror = new Set(htmlIn(MIRROR_DIR));
  for (const f of source) {
    if (!mirror.has(f)) {
      problems.push(`docs/spec/${f} is missing (spec-public/spec/${f} exists)`);
      continue;
    }
    mirror.delete(f);
    if (!readFileSync(join(SOURCE_DIR, f)).equals(readFileSync(join(MIRROR_DIR, f)))) {
      problems.push(`docs/spec/${f} differs from spec-public/spec/${f} (copy spec-public/spec/${f} over it)`);
    }
  }
  for (const f of mirror) problems.push(`docs/spec/${f} has no counterpart in spec-public/spec`);
  return problems;
}

let failed = false;
for (const pair of PAIRS) {
  const { problems, stats } = checkPair(pair);
  if (problems.length) {
    failed = true;
    console.error(`FAIL ${pair.md} -> ${pair.html} (${problems.length} problem(s))`);
    for (const p of problems) console.error(`  - ${p}`);
  } else {
    console.log(`ok   ${pair.md} -> ${pair.html} (${stats})`);
  }
}
const mirrorProblems = checkMirror();
if (mirrorProblems.length) {
  failed = true;
  console.error("FAIL docs/spec mirror");
  for (const p of mirrorProblems) console.error(`  - ${p}`);
} else {
  console.log("ok   docs/spec/*.html identical to spec-public/spec/*.html");
}
process.exit(failed ? 1 : 0);
