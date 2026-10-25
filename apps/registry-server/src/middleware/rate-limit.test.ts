import { describe, it, expect, vi, afterEach } from "vitest";
import { rateLimiter } from "./rate-limit.js";

afterEach(() => { vi.useRealTimers(); });

// Minimal Hono-context mock — the middleware only touches req.header, req.param, and c.json.
function makeCtx(ip = "1.2.3.4", params: Record<string, string> = {}) {
  return {
    req: {
      header: (name: string) =>
        name === "CF-Connecting-IP" || name === "Authorization" ? ip : undefined,
      param: (name: string) => params[name] ?? undefined,
    },
    json: (body: unknown, status: number, headers?: Record<string, string>) =>
      ({ body, status, headers }) as unknown as Response,
  };
}

async function call(
  mw: ReturnType<typeof rateLimiter>,
  ip = "1.2.3.4",
  params: Record<string, string> = {},
) {
  let nextCalled = false;
  const c = makeCtx(ip, params);
  const result = await mw(c as any, async () => { nextCalled = true; });
  return { nextCalled, result: result as { body: unknown; status: number; headers?: Record<string, string> } | undefined };
}

describe("rateLimiter — sliding window", () => {
  it("allows requests up to max", async () => {
    const mw = rateLimiter({ windowMs: 60_000, max: 3, keyFn: (c) => c.req.header("CF-Connecting-IP") ?? "x" });
    for (let i = 0; i < 3; i++) {
      const { nextCalled } = await call(mw);
      expect(nextCalled).toBe(true);
    }
  });

  it("blocks the (max+1)th request with HTTP 429", async () => {
    const mw = rateLimiter({ windowMs: 60_000, max: 2, keyFn: (c) => c.req.header("CF-Connecting-IP") ?? "x" });
    await call(mw);
    await call(mw);
    const { nextCalled, result } = await call(mw);
    expect(nextCalled).toBe(false);
    expect(result?.status).toBe(429);
  });

  it("429 response includes a positive Retry-After header", async () => {
    const mw = rateLimiter({ windowMs: 10_000, max: 1, keyFn: (c) => c.req.header("CF-Connecting-IP") ?? "x" });
    await call(mw);
    const { result } = await call(mw);
    const retryAfter = Number(result?.headers?.["Retry-After"]);
    expect(retryAfter).toBeGreaterThan(0);
  });

  it("uses the custom message in the 429 body", async () => {
    const mw = rateLimiter({ windowMs: 60_000, max: 1, message: "slow down", keyFn: () => "k" });
    await call(mw);
    const { result } = await call(mw);
    expect((result?.body as { error: string })?.error).toBe("slow down");
  });

  it("different keys are counted independently", async () => {
    const mw = rateLimiter({ windowMs: 60_000, max: 1, keyFn: (c) => c.req.header("CF-Connecting-IP") ?? "x" });
    await call(mw, "10.0.0.1");  // fills ip1's bucket
    const { nextCalled } = await call(mw, "10.0.0.2");  // ip2 has its own clean bucket
    expect(nextCalled).toBe(true);
  });

  it("bucket resets after the window expires", async () => {
    vi.useFakeTimers();
    const mw = rateLimiter({ windowMs: 1_000, max: 1, keyFn: (c) => c.req.header("CF-Connecting-IP") ?? "x" });
    await call(mw);
    const { nextCalled: blocked } = await call(mw);
    expect(blocked).toBe(false);

    vi.advanceTimersByTime(1_001);  // past the window
    const { nextCalled: allowed } = await call(mw);
    expect(allowed).toBe(true);
  });

  it("prunes expired entries when map exceeds 5 000 keys", async () => {
    vi.useFakeTimers();
    const mw = rateLimiter({ windowMs: 100, max: 100, keyFn: (c) => c.req.header("CF-Connecting-IP") ?? "x" });

    // Fill 5 000 distinct buckets
    for (let i = 0; i < 5_000; i++) {
      await call(mw, `${(i >> 8) & 0xff}.${i & 0xff}.0.0`);
    }
    // Advance so all 5 000 buckets are expired
    vi.advanceTimersByTime(200);

    // The 5 001st request triggers the GC prune and must still pass
    const { nextCalled } = await call(mw, "99.99.99.99");
    expect(nextCalled).toBe(true);
  });
});
