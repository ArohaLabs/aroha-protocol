// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import type { Message, SessionStore } from "./types.js";

/**
 * In-memory session store. Suitable for single-process deployments.
 * For multi-replica deployments, use a Redis or Postgres adapter that
 * implements the same SessionStore interface.
 */
export class InMemorySessionStore implements SessionStore {
  private readonly sessions = new Map<string, Message[]>();

  async load(sessionId: string): Promise<Message[]> {
    return this.sessions.get(sessionId) ?? [];
  }

  async append(sessionId: string, messages: Message[]): Promise<void> {
    const existing = this.sessions.get(sessionId) ?? [];
    this.sessions.set(sessionId, [...existing, ...messages]);
  }

  async clear(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
  }
}
