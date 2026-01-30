import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, beforeAll } from "vitest";

import { applyHookMappings, resolveHookMappings } from "./hooks-mapping.js";
import { registerBuiltinAuthModes, webhookAuthRegistry } from "./webhook-auth-registry.js";

beforeAll(() => {
  // Ensure built-in auth modes are registered
  if (!webhookAuthRegistry.has("token")) {
    registerBuiltinAuthModes();
  }
});

const baseUrl = new URL("http://127.0.0.1:18789/hooks/gmail");

describe("hooks mapping", () => {
  it("resolves gmail preset", () => {
    const mappings = resolveHookMappings({ presets: ["gmail"] });
    expect(mappings.length).toBeGreaterThan(0);
    expect(mappings[0]?.matchPath).toBe("gmail");
  });

  it("renders template from payload", async () => {
    const mappings = resolveHookMappings({
      mappings: [
        {
          id: "demo",
          match: { path: "gmail" },
          action: "agent",
          messageTemplate: "Subject: {{messages[0].subject}}",
        },
      ],
    });
    const result = await applyHookMappings(mappings, {
      payload: { messages: [{ subject: "Hello" }] },
      headers: {},
      url: baseUrl,
      path: "gmail",
    });
    expect(result?.ok).toBe(true);
    if (result?.ok) {
      expect(result.action.kind).toBe("agent");
      expect(result.action.message).toBe("Subject: Hello");
    }
  });

  it("passes model override from mapping", async () => {
    const mappings = resolveHookMappings({
      mappings: [
        {
          id: "demo",
          match: { path: "gmail" },
          action: "agent",
          messageTemplate: "Subject: {{messages[0].subject}}",
          model: "openai/gpt-4.1-mini",
        },
      ],
    });
    const result = await applyHookMappings(mappings, {
      payload: { messages: [{ subject: "Hello" }] },
      headers: {},
      url: baseUrl,
      path: "gmail",
    });
    expect(result?.ok).toBe(true);
    if (result?.ok && result.action.kind === "agent") {
      expect(result.action.model).toBe("openai/gpt-4.1-mini");
    }
  });

  it("runs transform module", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-hooks-"));
    const modPath = path.join(dir, "transform.mjs");
    const placeholder = "${" + "payload.name}";
    fs.writeFileSync(
      modPath,
      `export default ({ payload }) => ({ kind: "wake", text: \`Ping ${placeholder}\` });`,
    );

    const mappings = resolveHookMappings({
      transformsDir: dir,
      mappings: [
        {
          match: { path: "custom" },
          action: "agent",
          transform: { module: "transform.mjs" },
        },
      ],
    });

    const result = await applyHookMappings(mappings, {
      payload: { name: "Ada" },
      headers: {},
      url: new URL("http://127.0.0.1:18789/hooks/custom"),
      path: "custom",
    });

    expect(result?.ok).toBe(true);
    if (result?.ok) {
      expect(result.action.kind).toBe("wake");
      if (result.action.kind === "wake") {
        expect(result.action.text).toBe("Ping Ada");
      }
    }
  });

  it("treats null transform as a handled skip", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-hooks-skip-"));
    const modPath = path.join(dir, "transform.mjs");
    fs.writeFileSync(modPath, "export default () => null;");

    const mappings = resolveHookMappings({
      transformsDir: dir,
      mappings: [
        {
          match: { path: "skip" },
          action: "agent",
          transform: { module: "transform.mjs" },
        },
      ],
    });

    const result = await applyHookMappings(mappings, {
      payload: {},
      headers: {},
      url: new URL("http://127.0.0.1:18789/hooks/skip"),
      path: "skip",
    });

    expect(result?.ok).toBe(true);
    if (result?.ok) {
      expect(result.action).toBeNull();
      expect("skipped" in result).toBe(true);
    }
  });

  it("prefers explicit mappings over presets", async () => {
    const mappings = resolveHookMappings({
      presets: ["gmail"],
      mappings: [
        {
          id: "override",
          match: { path: "gmail" },
          action: "agent",
          messageTemplate: "Override subject: {{messages[0].subject}}",
        },
      ],
    });
    const result = await applyHookMappings(mappings, {
      payload: { messages: [{ subject: "Hello" }] },
      headers: {},
      url: baseUrl,
      path: "gmail",
    });
    expect(result?.ok).toBe(true);
    if (result?.ok) {
      expect(result.action.kind).toBe("agent");
      expect(result.action.message).toBe("Override subject: Hello");
    }
  });

  it("rejects missing message", async () => {
    const mappings = resolveHookMappings({
      mappings: [{ match: { path: "noop" }, action: "agent" }],
    });
    const result = await applyHookMappings(mappings, {
      payload: {},
      headers: {},
      url: new URL("http://127.0.0.1:18789/hooks/noop"),
      path: "noop",
    });
    expect(result?.ok).toBe(false);
  });
});

describe("webhook auth configuration", () => {
  it("defaults to token auth when no auth specified", () => {
    const mappings = resolveHookMappings({
      mappings: [
        {
          id: "default-auth",
          match: { path: "test" },
          action: "agent",
          messageTemplate: "Test",
        },
      ],
    });
    expect(mappings[0]?.authMode).toBeDefined();
    expect(mappings[0]?.authConfig).toBeDefined();
  });

  it("resolves explicit token auth", () => {
    const mappings = resolveHookMappings({
      mappings: [
        {
          id: "explicit-token",
          match: { path: "test" },
          action: "agent",
          messageTemplate: "Test",
          auth: { mode: "token", token: "secret123" },
        },
      ],
    });
    expect(mappings[0]?.authMode).toBeDefined();
    expect(mappings[0]?.authConfig?.token).toBe("secret123");
  });

  it("resolves hmac auth with defaults", () => {
    const mappings = resolveHookMappings({
      mappings: [
        {
          id: "hmac-auth",
          match: { path: "test" },
          action: "agent",
          messageTemplate: "Test",
          auth: {
            mode: "hmac",
            header: "x-signature",
            secret: "my-secret",
          },
        },
      ],
    });
    expect(mappings[0]?.authMode).toBeDefined();
    // Defaults merged in
    expect(mappings[0]?.authConfig?.algorithm).toBe("sha256");
    expect(mappings[0]?.authConfig?.encoding).toBe("hex");
    expect(mappings[0]?.authConfig?.header).toBe("x-signature");
  });

  it("resolves hmac auth with github-style config", () => {
    const mappings = resolveHookMappings({
      mappings: [
        {
          id: "github-auth",
          match: { path: "github" },
          action: "agent",
          messageTemplate: "Test",
          auth: {
            mode: "hmac",
            header: "x-hub-signature-256",
            secret: "my-secret",
            prefix: "sha256=",
          },
        },
      ],
    });
    expect(mappings[0]?.authMode).toBeDefined();
    expect(mappings[0]?.authConfig?.header).toBe("x-hub-signature-256");
    expect(mappings[0]?.authConfig?.prefix).toBe("sha256=");
    expect(mappings[0]?.authConfig?.secret).toBe("my-secret");
  });

  it("throws on unknown auth mode", () => {
    expect(() =>
      resolveHookMappings({
        mappings: [
          {
            id: "unknown-auth",
            match: { path: "test" },
            action: "agent",
            messageTemplate: "Test",
            auth: { mode: "unknown-mode" },
          },
        ],
      }),
    ).toThrow('unknown auth mode "unknown-mode"');
  });

  it("auth mode verifies correctly", async () => {
    const mappings = resolveHookMappings({
      mappings: [
        {
          id: "token-auth",
          match: { path: "test" },
          action: "agent",
          messageTemplate: "Test",
          auth: { mode: "token", token: "secret123" },
        },
      ],
    });
    const { authMode, authConfig } = mappings[0]!;
    expect(authMode).toBeDefined();
    if (authMode && authConfig) {
      const validCtx = {
        headers: { authorization: "Bearer secret123" },
        url: new URL("http://localhost/hooks/test"),
        path: "test",
        rawBody: Buffer.from("{}"),
      };
      const invalidCtx = {
        headers: { authorization: "Bearer wrong" },
        url: new URL("http://localhost/hooks/test"),
        path: "test",
        rawBody: Buffer.from("{}"),
      };
      expect(await authMode.verifyWebhook(validCtx, authConfig)).toBe(true);
      expect(await authMode.verifyWebhook(invalidCtx, authConfig)).toBe(false);
    }
  });
});
