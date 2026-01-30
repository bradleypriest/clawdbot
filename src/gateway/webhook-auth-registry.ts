import { createHmac, timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";

/**
 * Context provided to webhook auth verifiers.
 */
export type WebhookAuthContext = {
  headers: Record<string, string>;
  url: URL;
  path: string;
  rawBody: Buffer;
};

/**
 * A webhook auth mode.
 * verifyWebhook receives the request context and the resolved config
 * (user config merged on top of defaults).
 */
export type WebhookAuthMode = {
  verifyWebhook: (
    ctx: WebhookAuthContext,
    config: Record<string, unknown>,
  ) => boolean | Promise<boolean>;
  defaults?: Record<string, unknown>;
  configSchema?: Record<string, unknown>;
};

/**
 * Global registry of webhook auth modes.
 */
class WebhookAuthRegistry {
  private modes = new Map<string, WebhookAuthMode>();

  register(mode: string, handler: WebhookAuthMode): void {
    if (this.modes.has(mode)) {
      throw new Error(`webhook auth mode "${mode}" already registered`);
    }
    this.modes.set(mode, handler);
  }

  resolve(mode: string): WebhookAuthMode | undefined {
    return this.modes.get(mode);
  }

  has(mode: string): boolean {
    return this.modes.has(mode);
  }

  listModes(): string[] {
    return Array.from(this.modes.keys());
  }
}

export const webhookAuthRegistry = new WebhookAuthRegistry();

// =============================================================================
// Built-in Auth Modes
// =============================================================================

/**
 * Token-based auth mode (bearer, header, or query param).
 * Config: { mode: "token", token?: string }
 * If token is omitted, falls back to global hooks.token.
 */
export const tokenAuthMode: WebhookAuthMode = {
  verifyWebhook: (ctx, config) => {
    const expectedToken = typeof config.token === "string" ? config.token.trim() : undefined;
    const providedToken = extractToken(ctx);
    if (!providedToken) return false;
    if (!expectedToken) return !!providedToken;
    try {
      return timingSafeEqual(Buffer.from(expectedToken), Buffer.from(providedToken));
    } catch {
      return false;
    }
  },
};

/**
 * HMAC signature verification auth mode.
 * Config: { mode: "hmac", header, secret, algorithm?, encoding?, prefix? }
 */
export const hmacAuthMode: WebhookAuthMode = {
  defaults: {
    algorithm: "sha256",
    encoding: "hex",
  },
  verifyWebhook: (ctx, config) => {
    const header = typeof config.header === "string" ? config.header.toLowerCase().trim() : "";
    const secret = typeof config.secret === "string" ? config.secret : "";
    const algorithm = typeof config.algorithm === "string" ? config.algorithm : "sha256";
    const encoding = typeof config.encoding === "string" ? config.encoding : "hex";
    const prefix = typeof config.prefix === "string" ? config.prefix : "";

    if (!header || !secret) return false;

    const signatureHeader = ctx.headers[header];
    if (!signatureHeader) return false;

    const signature =
      prefix && signatureHeader.startsWith(prefix)
        ? signatureHeader.slice(prefix.length)
        : signatureHeader;

    const hmac = createHmac(algorithm, secret);
    hmac.update(ctx.rawBody);
    const expected = hmac.digest(encoding as "hex" | "base64");

    try {
      return timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
    } catch {
      return false;
    }
  },
};

/**
 * Helper to extract token from context (bearer, header, or query).
 */
function extractToken(ctx: WebhookAuthContext): string | undefined {
  const auth = ctx.headers.authorization ?? ctx.headers.Authorization ?? "";
  if (auth.toLowerCase().startsWith("bearer ")) {
    const token = auth.slice(7).trim();
    if (token) return token;
  }

  const headerToken = ctx.headers["x-openclaw-token"] ?? ctx.headers["X-OpenClaw-Token"] ?? "";
  if (headerToken) return headerToken.trim();

  const queryToken = ctx.url.searchParams.get("token");
  if (queryToken) return queryToken.trim();

  return undefined;
}

/**
 * Resolve config for an auth mode — merges defaults under user config.
 */
export function resolveAuthConfig(
  mode: WebhookAuthMode,
  userConfig: Record<string, unknown>,
): Record<string, unknown> {
  if (!mode.defaults) return userConfig;
  return { ...mode.defaults, ...userConfig };
}

/**
 * Register all built-in auth modes.
 */
export function registerBuiltinAuthModes(): void {
  webhookAuthRegistry.register("token", tokenAuthMode);
  webhookAuthRegistry.register("hmac", hmacAuthMode);
}

/**
 * Create a raw body reader for IncomingMessage.
 */
export async function readRawBody(req: IncomingMessage, maxBytes: number): Promise<Buffer | null> {
  return await new Promise((resolve) => {
    let done = false;
    let total = 0;
    const chunks: Buffer[] = [];

    req.on("data", (chunk: Buffer) => {
      if (done) return;
      total += chunk.length;
      if (total > maxBytes) {
        done = true;
        resolve(null);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      if (done) return;
      done = true;
      resolve(Buffer.concat(chunks));
    });

    req.on("error", () => {
      if (done) return;
      done = true;
      resolve(null);
    });
  });
}
