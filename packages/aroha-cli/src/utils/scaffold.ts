// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { mkdir, writeFile, access } from "node:fs/promises";
import { dirname, join } from "node:path";

export async function writeScaffold(
  outDir: string,
  files: Map<string, string>
): Promise<void> {
  for (const [rel, content] of files) {
    const abs = join(outDir, rel);
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, content, "utf8");
    log("create", rel);
  }
}

export async function dirExists(p: string): Promise<boolean> {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

export function log(tag: string, msg: string): void {
  const colors: Record<string, string> = {
    create: "\x1b[32m",   // green
    skip:   "\x1b[33m",   // yellow
    error:  "\x1b[31m",   // red
    info:   "\x1b[36m",   // cyan
    done:   "\x1b[35m",   // magenta
  };
  const reset = "\x1b[0m";
  const color = colors[tag] ?? "";
  console.log(`  ${color}${tag.padEnd(8)}${reset} ${msg}`);
}

export function banner(title: string): void {
  console.log(`\n\x1b[1m${title}\x1b[0m`);
  console.log("─".repeat(title.length + 2));
}

export function success(msg: string): void {
  console.log(`\n\x1b[32m✓\x1b[0m ${msg}\n`);
}

export function fatal(msg: string): never {
  console.error(`\n\x1b[31m✗\x1b[0m ${msg}\n`);
  process.exit(1);
}
