// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { type IncomingMessage } from "http";

export function readBody(req: IncomingMessage, maxBytes = 1_048_576): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    let settled = false;

    const done = (fn: () => void) => {
      if (settled) return;
      settled = true;
      fn();
    };

    req.on("data", (chunk: Buffer) => {
      totalBytes += chunk.length;
      if (totalBytes > maxBytes) {
        const err = new Error("PAYLOAD_TOO_LARGE");
        (err as NodeJS.ErrnoException).code = "PAYLOAD_TOO_LARGE";
        done(() => reject(err));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => done(() => resolve(Buffer.concat(chunks).toString("utf8"))));
    req.on("error", (err) => done(() => reject(err)));
  });
}
