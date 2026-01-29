import { randomUUID } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { listChannelPlugins } from "../channels/plugins/index.js";
import type { ChannelId } from "../channels/plugins/types.js";
import type { MoltbotConfig } from "../config/config.js";
import { normalizeMessageChannel } from "../utils/message-channel.js";
import {
  findMappingVerifyAuth,
  type HookMappingResolved,
  type HookVerifyAuthFn,
  resolveHookMappings,
} from "./hooks-mapping.js";

const DEFAULT_HOOKS_PATH = "/hooks";
const DEFAULT_HOOKS_MAX_BODY_BYTES = 256 * 1024;

export type HooksConfigResolved = {
  basePath: string;
  token: string;
  maxBodyBytes: number;
  mappings: HookMappingResolved[];
};

export function resolveHooksConfig(cfg: MoltbotConfig): HooksConfigResolved | null {
  if (cfg.hooks?.enabled !== true) return null;
  const token = cfg.hooks?.token?.trim();
  if (!token) {
    throw new Error("hooks.enabled requires hooks.token");
  }
  const rawPath = cfg.hooks?.path?.trim() || DEFAULT_HOOKS_PATH;
  const withSlash = rawPath.startsWith("/") ? rawPath : `/${rawPath}`;
  const trimmed = withSlash.length > 1 ? withSlash.replace(/\/+$/, "") : withSlash;
  if (trimmed === "/") {
    throw new Error("hooks.path may not be '/'");
  }
  const maxBodyBytes =
    cfg.hooks?.maxBodyBytes && cfg.hooks.maxBodyBytes > 0
      ? cfg.hooks.maxBodyBytes
      : DEFAULT_HOOKS_MAX_BODY_BYTES;
  const mappings = resolveHookMappings(cfg.hooks);
  return {
    basePath: trimmed,
    token,
    maxBodyBytes,
    mappings,
  };
}

export type HookTokenResult = {
  token: string | undefined;
  fromQuery: boolean;
};

export function extractHookToken(req: IncomingMessage, url: URL): HookTokenResult {
  const auth =
    typeof req.headers.authorization === "string" ? req.headers.authorization.trim() : "";
  if (auth.toLowerCase().startsWith("bearer ")) {
    const token = auth.slice(7).trim();
    if (token) return { token, fromQuery: false };
  }
  const headerToken =
    typeof req.headers["x-moltbot-token"] === "string" ? req.headers["x-moltbot-token"].trim() : "";
  if (headerToken) return { token: headerToken, fromQuery: false };
  const queryToken = url.searchParams.get("token");
  if (queryToken) return { token: queryToken.trim(), fromQuery: true };
  return { token: undefined, fromQuery: false };
}

export async function readRawBody(
  req: IncomingMessage,
  maxBytes: number,
): Promise<{ ok: true; value: Buffer } | { ok: false; error: string }> {
  return await new Promise((resolve) => {
    let done = false;
    let total = 0;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      if (done) return;
      total += chunk.length;
      if (total > maxBytes) {
        done = true;
        resolve({ ok: false, error: "payload too large" });
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (done) return;
      done = true;
      resolve({ ok: true, value: Buffer.concat(chunks) });
    });
    req.on("error", (err) => {
      if (done) return;
      done = true;
      resolve({ ok: false, error: String(err) });
    });
  });
}

export function parseJsonBody(
  raw: Buffer,
): { ok: true; value: unknown } | { ok: false; error: string } {
  const str = raw.toString("utf-8").trim();
  if (!str) {
    return { ok: true, value: {} };
  }
  try {
    const parsed = JSON.parse(str) as unknown;
    return { ok: true, value: parsed };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}

export async function readJsonBody(
  req: IncomingMessage,
  maxBytes: number,
): Promise<{ ok: true; value: unknown } | { ok: false; error: string }> {
  const raw = await readRawBody(req, maxBytes);
  if (!raw.ok) return raw;
  return parseJsonBody(raw.value);
}

export type VerifyWebhookContext = {
  req: IncomingMessage;
  url: URL;
  subPath: string;
  headers: Record<string, string>;
  mappings: HookMappingResolved[];
  expectedToken: string;
  maxBodyBytes: number;
};

export type VerifyWebhookResult =
  | { ok: true; payload: Record<string, unknown>; tokenFromQuery: boolean }
  | { ok: false; status: number; error: string };

/**
 * Verify webhook authentication and parse body.
 *
 * Checks for custom verifyAuth from matching mapping first,
 * falls back to standard token auth otherwise.
 */
export async function verifyWebhook(ctx: VerifyWebhookContext): Promise<VerifyWebhookResult> {
  const { req, url, subPath, headers, mappings, expectedToken, maxBodyBytes } = ctx;

  // Check for custom auth via mapping transform's verifyAuth export
  const customVerifyAuth = await findMappingVerifyAuth(mappings, subPath);

  if (customVerifyAuth) {
    return verifyWithCustomAuth(req, url, subPath, headers, customVerifyAuth, maxBodyBytes);
  }

  return verifyWithToken(req, url, expectedToken, maxBodyBytes);
}

async function verifyWithCustomAuth(
  req: IncomingMessage,
  url: URL,
  subPath: string,
  headers: Record<string, string>,
  verifyAuth: HookVerifyAuthFn,
  maxBodyBytes: number,
): Promise<VerifyWebhookResult> {
  // Read raw body for signature verification
  const rawBody = await readRawBody(req, maxBodyBytes);
  if (!rawBody.ok) {
    const status = rawBody.error === "payload too large" ? 413 : 400;
    return { ok: false, status, error: rawBody.error };
  }

  // Call custom verifyAuth function
  const authCtx = { headers, url, path: subPath, rawBody: rawBody.value };
  let authResult: boolean;
  try {
    authResult = await verifyAuth(authCtx);
  } catch (err) {
    return { ok: false, status: 401, error: `verifyAuth error: ${String(err)}` };
  }

  if (!authResult) {
    return { ok: false, status: 401, error: "Unauthorized" };
  }

  // Auth passed, parse the JSON body from the raw buffer
  const parsed = parseJsonBody(rawBody.value);
  if (!parsed.ok) {
    return { ok: false, status: 400, error: parsed.error };
  }

  const payload =
    typeof parsed.value === "object" && parsed.value !== null
      ? (parsed.value as Record<string, unknown>)
      : {};

  return { ok: true, payload, tokenFromQuery: false };
}

async function verifyWithToken(
  req: IncomingMessage,
  url: URL,
  expectedToken: string,
  maxBodyBytes: number,
): Promise<VerifyWebhookResult> {
  const { token, fromQuery } = extractHookToken(req, url);
  if (!token || token !== expectedToken) {
    return { ok: false, status: 401, error: "Unauthorized" };
  }

  const body = await readJsonBody(req, maxBodyBytes);
  if (!body.ok) {
    const status = body.error === "payload too large" ? 413 : 400;
    return { ok: false, status, error: body.error };
  }

  const payload =
    typeof body.value === "object" && body.value !== null
      ? (body.value as Record<string, unknown>)
      : {};

  return { ok: true, payload, tokenFromQuery: fromQuery };
}

export function normalizeHookHeaders(req: IncomingMessage) {
  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(req.headers)) {
    if (typeof value === "string") {
      headers[key.toLowerCase()] = value;
    } else if (Array.isArray(value) && value.length > 0) {
      headers[key.toLowerCase()] = value.join(", ");
    }
  }
  return headers;
}

export function normalizeWakePayload(
  payload: Record<string, unknown>,
):
  | { ok: true; value: { text: string; mode: "now" | "next-heartbeat" } }
  | { ok: false; error: string } {
  const text = typeof payload.text === "string" ? payload.text.trim() : "";
  if (!text) return { ok: false, error: "text required" };
  const mode = payload.mode === "next-heartbeat" ? "next-heartbeat" : "now";
  return { ok: true, value: { text, mode } };
}

export type HookAgentPayload = {
  message: string;
  name: string;
  wakeMode: "now" | "next-heartbeat";
  sessionKey: string;
  deliver: boolean;
  channel: HookMessageChannel;
  to?: string;
  model?: string;
  thinking?: string;
  timeoutSeconds?: number;
};

const listHookChannelValues = () => ["last", ...listChannelPlugins().map((plugin) => plugin.id)];

export type HookMessageChannel = ChannelId | "last";

const getHookChannelSet = () => new Set<string>(listHookChannelValues());
export const getHookChannelError = () => `channel must be ${listHookChannelValues().join("|")}`;

export function resolveHookChannel(raw: unknown): HookMessageChannel | null {
  if (raw === undefined) return "last";
  if (typeof raw !== "string") return null;
  const normalized = normalizeMessageChannel(raw);
  if (!normalized || !getHookChannelSet().has(normalized)) return null;
  return normalized as HookMessageChannel;
}

export function resolveHookDeliver(raw: unknown): boolean {
  return raw !== false;
}

export function normalizeAgentPayload(
  payload: Record<string, unknown>,
  opts?: { idFactory?: () => string },
):
  | {
      ok: true;
      value: HookAgentPayload;
    }
  | { ok: false; error: string } {
  const message = typeof payload.message === "string" ? payload.message.trim() : "";
  if (!message) return { ok: false, error: "message required" };
  const nameRaw = payload.name;
  const name = typeof nameRaw === "string" && nameRaw.trim() ? nameRaw.trim() : "Hook";
  const wakeMode = payload.wakeMode === "next-heartbeat" ? "next-heartbeat" : "now";
  const sessionKeyRaw = payload.sessionKey;
  const idFactory = opts?.idFactory ?? randomUUID;
  const sessionKey =
    typeof sessionKeyRaw === "string" && sessionKeyRaw.trim()
      ? sessionKeyRaw.trim()
      : `hook:${idFactory()}`;
  const channel = resolveHookChannel(payload.channel);
  if (!channel) return { ok: false, error: getHookChannelError() };
  const toRaw = payload.to;
  const to = typeof toRaw === "string" && toRaw.trim() ? toRaw.trim() : undefined;
  const modelRaw = payload.model;
  const model = typeof modelRaw === "string" && modelRaw.trim() ? modelRaw.trim() : undefined;
  if (modelRaw !== undefined && !model) {
    return { ok: false, error: "model required" };
  }
  const deliver = resolveHookDeliver(payload.deliver);
  const thinkingRaw = payload.thinking;
  const thinking =
    typeof thinkingRaw === "string" && thinkingRaw.trim() ? thinkingRaw.trim() : undefined;
  const timeoutRaw = payload.timeoutSeconds;
  const timeoutSeconds =
    typeof timeoutRaw === "number" && Number.isFinite(timeoutRaw) && timeoutRaw > 0
      ? Math.floor(timeoutRaw)
      : undefined;
  return {
    ok: true,
    value: {
      message,
      name,
      wakeMode,
      sessionKey,
      deliver,
      channel,
      to,
      model,
      thinking,
      timeoutSeconds,
    },
  };
}
