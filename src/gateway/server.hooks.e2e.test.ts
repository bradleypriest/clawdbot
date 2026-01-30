import { describe, expect, test } from "vitest";
import { resolveMainSessionKeyFromConfig } from "../config/sessions.js";
import { drainSystemEvents, peekSystemEvents } from "../infra/system-events.js";
import {
  cronIsolatedRun,
  getFreePort,
  installGatewayTestHooks,
  startGatewayServer,
  testState,
  waitForSystemEvent,
} from "./test-helpers.js";

installGatewayTestHooks({ scope: "suite" });

const resolveMainKey = () => resolveMainSessionKeyFromConfig();

describe("gateway server hooks", () => {
  test("handles auth, wake, and agent flows", async () => {
    testState.hooksConfig = { enabled: true, token: "hook-secret" };
    const port = await getFreePort();
    const server = await startGatewayServer(port);
    try {
      const resNoAuth = await fetch(`http://127.0.0.1:${port}/hooks/wake`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: "Ping" }),
      });
      expect(resNoAuth.status).toBe(401);

      const resWake = await fetch(`http://127.0.0.1:${port}/hooks/wake`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer hook-secret",
        },
        body: JSON.stringify({ text: "Ping", mode: "next-heartbeat" }),
      });
      expect(resWake.status).toBe(200);
      const wakeEvents = await waitForSystemEvent();
      expect(wakeEvents.some((e) => e.includes("Ping"))).toBe(true);
      drainSystemEvents(resolveMainKey());

      cronIsolatedRun.mockReset();
      cronIsolatedRun.mockResolvedValueOnce({
        status: "ok",
        summary: "done",
      });
      const resAgent = await fetch(`http://127.0.0.1:${port}/hooks/agent`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer hook-secret",
        },
        body: JSON.stringify({ message: "Do it", name: "Email" }),
      });
      expect(resAgent.status).toBe(202);
      const agentEvents = await waitForSystemEvent();
      expect(agentEvents.some((e) => e.includes("Hook Email: done"))).toBe(true);
      drainSystemEvents(resolveMainKey());

      cronIsolatedRun.mockReset();
      cronIsolatedRun.mockResolvedValueOnce({
        status: "ok",
        summary: "done",
      });
      const resAgentModel = await fetch(`http://127.0.0.1:${port}/hooks/agent`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer hook-secret",
        },
        body: JSON.stringify({
          message: "Do it",
          name: "Email",
          model: "openai/gpt-4.1-mini",
        }),
      });
      expect(resAgentModel.status).toBe(202);
      await waitForSystemEvent();
      const call = cronIsolatedRun.mock.calls[0]?.[0] as {
        job?: { payload?: { model?: string } };
      };
      expect(call?.job?.payload?.model).toBe("openai/gpt-4.1-mini");
      drainSystemEvents(resolveMainKey());

      const resQuery = await fetch(`http://127.0.0.1:${port}/hooks/wake?token=hook-secret`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: "Query auth" }),
      });
      expect(resQuery.status).toBe(200);
      const queryEvents = await waitForSystemEvent();
      expect(queryEvents.some((e) => e.includes("Query auth"))).toBe(true);
      drainSystemEvents(resolveMainKey());

      const resBadChannel = await fetch(`http://127.0.0.1:${port}/hooks/agent`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer hook-secret",
        },
        body: JSON.stringify({ message: "Nope", channel: "sms" }),
      });
      expect(resBadChannel.status).toBe(400);
      expect(peekSystemEvents(resolveMainKey()).length).toBe(0);

      const resHeader = await fetch(`http://127.0.0.1:${port}/hooks/wake`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-openclaw-token": "hook-secret",
        },
        body: JSON.stringify({ text: "Header auth" }),
      });
      expect(resHeader.status).toBe(200);
      const headerEvents = await waitForSystemEvent();
      expect(headerEvents.some((e) => e.includes("Header auth"))).toBe(true);
      drainSystemEvents(resolveMainKey());

      const resGet = await fetch(`http://127.0.0.1:${port}/hooks/wake`, {
        method: "GET",
        headers: { Authorization: "Bearer hook-secret" },
      });
      expect(resGet.status).toBe(405);

      const resBlankText = await fetch(`http://127.0.0.1:${port}/hooks/wake`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer hook-secret",
        },
        body: JSON.stringify({ text: " " }),
      });
      expect(resBlankText.status).toBe(400);

      const resBlankMessage = await fetch(`http://127.0.0.1:${port}/hooks/agent`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer hook-secret",
        },
        body: JSON.stringify({ message: " " }),
      });
      expect(resBlankMessage.status).toBe(400);

      const resBadJson = await fetch(`http://127.0.0.1:${port}/hooks/wake`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer hook-secret",
        },
        body: "{",
      });
      expect(resBadJson.status).toBe(400);
    } finally {
      await server.close();
    }
  });

  test("handles per-mapping auth modes", async () => {
    const { createHmac } = await import("node:crypto");
    testState.hooksConfig = {
      enabled: true,
      token: "global-token",
      mappings: [
        {
          id: "hmac-test",
          match: { path: "hmac" },
          action: "wake",
          textTemplate: "HMAC webhook: {{payload.message}}",
          auth: {
            mode: "hmac",
            header: "x-signature",
            secret: "hmac-secret",
            algorithm: "sha256",
            encoding: "hex",
          },
        },
        {
          id: "none-test",
          match: { path: "public" },
          action: "wake",
          textTemplate: "Public webhook: {{payload.message}}",
          auth: { mode: "none" },
        },
        {
          id: "token-test",
          match: { path: "custom-token" },
          action: "wake",
          textTemplate: "Custom token: {{payload.message}}",
          auth: {
            mode: "token",
            token: "custom-secret",
          },
        },
      ],
    };

    const port = await getFreePort();
    const server = await startGatewayServer(port);
    try {
      // Test HMAC auth - valid signature
      const hmacBody = JSON.stringify({ message: "test hmac" });
      const hmacSignature = createHmac("sha256", "hmac-secret").update(hmacBody).digest("hex");
      const resHmacValid = await fetch(`http://127.0.0.1:${port}/hooks/hmac`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-signature": hmacSignature,
        },
        body: hmacBody,
      });
      expect(resHmacValid.status).toBe(200);
      const hmacEvents = await waitForSystemEvent();
      expect(hmacEvents.some((e) => e.includes("HMAC webhook: test hmac"))).toBe(true);
      drainSystemEvents(resolveMainKey());

      // Test HMAC auth - invalid signature
      const resHmacInvalid = await fetch(`http://127.0.0.1:${port}/hooks/hmac`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-signature": "invalid-signature",
        },
        body: JSON.stringify({ message: "bad" }),
      });
      expect(resHmacInvalid.status).toBe(401);
      expect(peekSystemEvents(resolveMainKey()).length).toBe(0);

      // Test none auth - no credentials required
      const resNone = await fetch(`http://127.0.0.1:${port}/hooks/public`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: "public" }),
      });
      expect(resNone.status).toBe(200);
      const noneEvents = await waitForSystemEvent();
      expect(noneEvents.some((e) => e.includes("Public webhook: public"))).toBe(true);
      drainSystemEvents(resolveMainKey());

      // Test custom token auth - valid token
      const resTokenValid = await fetch(`http://127.0.0.1:${port}/hooks/custom-token`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer custom-secret",
        },
        body: JSON.stringify({ message: "custom" }),
      });
      expect(resTokenValid.status).toBe(200);
      const tokenEvents = await waitForSystemEvent();
      expect(tokenEvents.some((e) => e.includes("Custom token: custom"))).toBe(true);
      drainSystemEvents(resolveMainKey());

      // Test custom token auth - wrong token
      const resTokenInvalid = await fetch(`http://127.0.0.1:${port}/hooks/custom-token`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer wrong-token",
        },
        body: JSON.stringify({ message: "wrong" }),
      });
      expect(resTokenInvalid.status).toBe(401);
      expect(peekSystemEvents(resolveMainKey()).length).toBe(0);

      // Test custom token auth - global token should not work
      const resTokenGlobal = await fetch(`http://127.0.0.1:${port}/hooks/custom-token`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer global-token",
        },
        body: JSON.stringify({ message: "global" }),
      });
      expect(resTokenGlobal.status).toBe(401);
      expect(peekSystemEvents(resolveMainKey()).length).toBe(0);
    } finally {
      await server.close();
    }
  });
});
