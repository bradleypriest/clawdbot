import { describe, test, expect, beforeEach } from "vitest";
import { createHmac } from "node:crypto";
import {
  webhookAuthRegistry,
  registerBuiltinAuthModes,
  tokenAuthMode,
  hmacAuthMode,
  resolveAuthConfig,
  type WebhookAuthContext,
} from "./webhook-auth-registry.js";

function createContext(headers: Record<string, string> = {}, body = "{}"): WebhookAuthContext {
  return {
    headers,
    url: new URL("http://localhost/hooks/test"),
    path: "test",
    rawBody: Buffer.from(body),
  };
}

describe("WebhookAuthRegistry", () => {
  beforeEach(() => {
    // Reset registry for each test
    const registry = webhookAuthRegistry as unknown as { modes: Map<string, unknown> };
    registry.modes.clear();
  });

  test("registers and resolves a mode", () => {
    const mode = { verifyWebhook: () => true };
    webhookAuthRegistry.register("test", mode);
    expect(webhookAuthRegistry.resolve("test")).toBe(mode);
  });

  test("throws on duplicate registration", () => {
    const mode = { verifyWebhook: () => true };
    webhookAuthRegistry.register("test", mode);
    expect(() => webhookAuthRegistry.register("test", mode)).toThrow("already registered");
  });

  test("returns undefined for unknown mode", () => {
    expect(webhookAuthRegistry.resolve("unknown")).toBeUndefined();
  });

  test("has() checks existence", () => {
    const mode = { verifyWebhook: () => true };
    webhookAuthRegistry.register("test", mode);
    expect(webhookAuthRegistry.has("test")).toBe(true);
    expect(webhookAuthRegistry.has("other")).toBe(false);
  });

  test("listModes returns registered modes", () => {
    webhookAuthRegistry.register("a", { verifyWebhook: () => true });
    webhookAuthRegistry.register("b", { verifyWebhook: () => true });
    expect(webhookAuthRegistry.listModes()).toEqual(["a", "b"]);
  });

  test("registerBuiltinAuthModes registers token and hmac", () => {
    registerBuiltinAuthModes();
    expect(webhookAuthRegistry.has("token")).toBe(true);
    expect(webhookAuthRegistry.has("hmac")).toBe(true);
  });
});

describe("resolveAuthConfig", () => {
  test("returns user config when no defaults", () => {
    const mode = { verifyWebhook: () => true };
    const config = resolveAuthConfig(mode, { secret: "abc" });
    expect(config).toEqual({ secret: "abc" });
  });

  test("merges defaults under user config", () => {
    const mode = {
      verifyWebhook: () => true,
      defaults: { algorithm: "sha256", encoding: "hex" },
    };
    const config = resolveAuthConfig(mode, { secret: "abc", encoding: "base64" });
    expect(config).toEqual({ algorithm: "sha256", encoding: "base64", secret: "abc" });
  });
});

describe("tokenAuthMode", () => {
  test("accepts valid bearer token", () => {
    const ctx = createContext({ authorization: "Bearer secret123" });
    expect(tokenAuthMode.verifyWebhook(ctx, { token: "secret123" })).toBe(true);
  });

  test("rejects invalid bearer token", () => {
    const ctx = createContext({ authorization: "Bearer wrong" });
    expect(tokenAuthMode.verifyWebhook(ctx, { token: "secret123" })).toBe(false);
  });

  test("rejects missing token", () => {
    const ctx = createContext({});
    expect(tokenAuthMode.verifyWebhook(ctx, { token: "secret123" })).toBe(false);
  });

  test("accepts x-openclaw-token header", () => {
    const ctx = createContext({ "x-openclaw-token": "secret123" });
    expect(tokenAuthMode.verifyWebhook(ctx, { token: "secret123" })).toBe(true);
  });

  test("accepts query param token", () => {
    const ctx: WebhookAuthContext = {
      headers: {},
      url: new URL("http://localhost/hooks/test?token=secret123"),
      path: "test",
      rawBody: Buffer.from("{}"),
    };
    expect(tokenAuthMode.verifyWebhook(ctx, { token: "secret123" })).toBe(true);
  });

  test("uses timing-safe comparison", () => {
    const ctx = createContext({ authorization: "Bearer secret123" });
    expect(tokenAuthMode.verifyWebhook(ctx, { token: "secret123" })).toBe(true);
    expect(tokenAuthMode.verifyWebhook(ctx, { token: "secret124" })).toBe(false);
  });
});

describe("hmacAuthMode", () => {
  const secret = "my-webhook-secret";
  const body = '{"event":"push"}';

  function sign(
    body: string,
    secret: string,
    opts?: { algorithm?: string; encoding?: "hex" | "base64"; prefix?: string },
  ): string {
    const algo = opts?.algorithm ?? "sha256";
    const enc = opts?.encoding ?? "hex";
    const prefix = opts?.prefix ?? "";
    return prefix + createHmac(algo, secret).update(body).digest(enc);
  }

  test("accepts valid HMAC-SHA256 hex signature", () => {
    const signature = sign(body, secret);
    const ctx = createContext({ "x-signature": signature }, body);
    expect(hmacAuthMode.verifyWebhook(ctx, { header: "x-signature", secret })).toBe(true);
  });

  test("rejects invalid signature", () => {
    const ctx = createContext({ "x-signature": "invalid" }, body);
    expect(hmacAuthMode.verifyWebhook(ctx, { header: "x-signature", secret })).toBe(false);
  });

  test("rejects missing signature header", () => {
    const ctx = createContext({}, body);
    expect(hmacAuthMode.verifyWebhook(ctx, { header: "x-signature", secret })).toBe(false);
  });

  test("rejects wrong secret", () => {
    const signature = sign(body, "wrong-secret");
    const ctx = createContext({ "x-signature": signature }, body);
    expect(hmacAuthMode.verifyWebhook(ctx, { header: "x-signature", secret })).toBe(false);
  });

  test("supports prefix stripping", () => {
    const signature = sign(body, secret, { prefix: "sha256=" });
    const ctx = createContext({ "x-signature": signature }, body);
    expect(
      hmacAuthMode.verifyWebhook(ctx, { header: "x-signature", secret, prefix: "sha256=" }),
    ).toBe(true);
  });

  test("supports base64 encoding", () => {
    const signature = sign(body, secret, { encoding: "base64" });
    const ctx = createContext({ "x-signature": signature }, body);
    expect(
      hmacAuthMode.verifyWebhook(ctx, { header: "x-signature", secret, encoding: "base64" }),
    ).toBe(true);
  });

  test("supports SHA-1 algorithm", () => {
    const signature = sign(body, secret, { algorithm: "sha1" });
    const ctx = createContext({ "x-signature": signature }, body);
    expect(
      hmacAuthMode.verifyWebhook(ctx, { header: "x-signature", secret, algorithm: "sha1" }),
    ).toBe(true);
  });

  test("returns false for missing header config", () => {
    const ctx = createContext({ "x-signature": "abc" }, body);
    expect(hmacAuthMode.verifyWebhook(ctx, { secret })).toBe(false);
  });

  test("returns false for missing secret config", () => {
    const ctx = createContext({ "x-signature": "abc" }, body);
    expect(hmacAuthMode.verifyWebhook(ctx, { header: "x-signature" })).toBe(false);
  });

  test("handles empty body", () => {
    const emptyBody = "";
    const signature = sign(emptyBody, secret);
    const ctx = createContext({ "x-signature": signature }, emptyBody);
    expect(hmacAuthMode.verifyWebhook(ctx, { header: "x-signature", secret })).toBe(true);
  });
});

describe("hmac mode with github-style config", () => {
  const secret = "github-secret";
  const body = '{"action":"opened"}';

  test("verifies github signatures using hmac mode with appropriate config", () => {
    const signature = "sha256=" + createHmac("sha256", secret).update(body).digest("hex");
    const ctx = createContext({ "x-hub-signature-256": signature }, body);
    const config = resolveAuthConfig(hmacAuthMode, {
      header: "x-hub-signature-256",
      secret,
      prefix: "sha256=",
    });
    expect(hmacAuthMode.verifyWebhook(ctx, config)).toBe(true);
  });

  test("rejects invalid github signature", () => {
    const ctx = createContext({ "x-hub-signature-256": "sha256=invalid" }, body);
    const config = resolveAuthConfig(hmacAuthMode, {
      header: "x-hub-signature-256",
      secret,
      prefix: "sha256=",
    });
    expect(hmacAuthMode.verifyWebhook(ctx, config)).toBe(false);
  });
});
