import { beforeEach, describe, expect, it, vi } from "vitest";
const { invoke } = vi.hoisted(() => ({ invoke: vi.fn(async () => null) }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

describe("beta diagnostics boundary", () => {
  beforeEach(() => {
    vi.resetModules();
    invoke.mockClear();
    vi.stubGlobal("window", {
      __TAURI_INTERNALS__: {},
      addEventListener: vi.fn(),
    });
  });
  it("never forwards rendered content, URLs or secrets", async () => {
    const { diagnosticErrorMessage } = await import("./diagnostics");
    diagnosticErrorMessage(
      "Failed for password=secret https://host/#invitation",
    );
    const body = JSON.stringify(invoke.mock.calls);
    expect(body).toContain("error.generic");
    expect(body).not.toMatch(/password|secret|https|invitation/);
  });
  it("reports a known error by resource key and deduplicates repeated renders", async () => {
    const { diagnosticErrorMessage } = await import("./diagnostics");
    diagnosticErrorMessage(
      "This action failed. If it keeps happening, contact support.",
    );
    diagnosticErrorMessage(
      "This action failed. If it keeps happening, contact support.",
    );
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledWith(
      "diagnostic_task",
      expect.objectContaining({
        request: expect.objectContaining({ code: "error.generic" }),
      }),
    );
  });
  it("observes unhandled failures without reading the event payload", async () => {
    const { installDiagnostics } = await import("./diagnostics");
    installDiagnostics(false);
    const calls = vi.mocked(window.addEventListener).mock.calls;
    const handler = calls.find(
      (call) => call[0] === "unhandledrejection",
    )![1] as (event: unknown) => void;
    const privateEvent = new Proxy(
      {},
      {
        get() {
          throw new Error("Private event accessed");
        },
      },
    );
    handler(privateEvent);
    expect(invoke).toHaveBeenLastCalledWith(
      "diagnostic_task",
      expect.objectContaining({
        request: expect.objectContaining({ code: "unhandled_rejection" }),
      }),
    );
  });
});
