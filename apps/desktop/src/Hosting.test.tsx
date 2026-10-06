import { expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { invoke } from "@tauri-apps/api/core";
import {
  chooseHosting,
  hostingCatalog,
  hostingErrorMessage,
  hostingLifetime,
  hostingAttachmentRequest,
  messageLifetimeLabel,
  type HostingProfileSummary,
} from "./Hosting";
import { HostingPicker, HostingPreview } from "./HostingPicker";
import { emptyAttachmentStorage } from "./AttachmentStorageForm";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

const publicHost: HostingProfileSummary = {
  id: "elo.now",
  name: "elo.now",
  url: "https://elo.example.invalid",
  message_lifetimes: [21_600, 43_200, 86_400],
  default_message_lifetime: 86_400,
  attachment_storage_available: false,
  attachment_storage_managed: false,
  builtin: true,
};
const customHost: HostingProfileSummary = {
  ...publicHost,
  id: "company",
  name: "Company",
  builtin: false,
  message_lifetimes: [43_200, 172_800, "no_expiry"],
  default_message_lifetime: 172_800,
  attachment_storage_available: true,
  attachment_storage_managed: true,
  storage_provider: "s3",
};

test("empty and changed catalogs never fabricate a default host", () => {
  expect(chooseHosting([], "elo.now")).toBeUndefined();
  expect(chooseHosting([customHost], "elo.now")).toBe(customHost);
  expect(chooseHosting([publicHost, customHost], "company")).toBe(customHost);
});

test("lifetimes follow the host's advertised choices and preserve explicit no expiry", () => {
  expect(hostingLifetime(customHost)).toBe(172_800);
  expect(hostingLifetime(customHost, "no_expiry")).toBe("no_expiry");
  expect(hostingLifetime(publicHost, "no_expiry")).toBe(86_400);
  expect(hostingLifetime(publicHost, 172_800)).toBe(86_400);
  expect(
    hostingLifetime({ ...customHost, message_lifetimes: [] }),
  ).toBeUndefined();
  expect(messageLifetimeLabel(172_800)).toBe("48 hours");
  expect(messageLifetimeLabel("no_expiry")).toBe("No automatic expiry");
});

test("managed attachments do not forward an old own-storage draft to the host", () => {
  const draft = {
    ...emptyAttachmentStorage(true),
    folder_link: "fixture-folder",
    write_auth: "fixture-write-key",
    secret_key: "fixture-secret",
  };
  expect(hostingAttachmentRequest(customHost, draft)).toEqual({
    enabled: true,
    managed: true,
  });
  expect(hostingAttachmentRequest(publicHost, draft)).toBeUndefined();
  expect(
    hostingAttachmentRequest(
      { ...customHost, attachment_storage_managed: false },
      draft,
    ),
  ).toEqual({
    enabled: true,
    provider: "mega_folder",
    folder_link: "fixture-folder",
    write_auth: "fixture-write-key",
  });
});

test("preview is a separate native request and does not add a hosting entry", async () => {
  vi.mocked(invoke)
    .mockReset()
    .mockResolvedValue({ entries: [publicHost], preview: customHost });
  await hostingCatalog({ op: "preview", link: "elo-hosting:test-fixture" });
  expect(invoke).toHaveBeenCalledExactlyOnceWith("hosting_catalog", {
    request: { op: "preview", link: "elo-hosting:test-fixture" },
  });
  await hostingCatalog({ op: "add", link: "elo-hosting:test-fixture" });
  expect(invoke).toHaveBeenLastCalledWith("hosting_catalog", {
    request: { op: "add", link: "elo-hosting:test-fixture" },
  });
});

test("hosting failures explain trust conflicts without exposing raw native data", () => {
  expect(
    hostingErrorMessage(
      "This hosting address already has an approved configuration.",
      "hosting.previewFailed",
    ),
  ).toContain("conflicts with the hosting configuration saved on this device");
  expect(
    hostingErrorMessage(
      "Add this hosting configuration before opening the invitation.",
      "hosting.previewFailed",
    ),
  ).toBe("Add this hosting configuration before opening the invitation.");
  expect(
    hostingErrorMessage(
      {
        message: "unrecognized fixture",
        url: "https://fixture.invalid/",
        key: "fixture-secret",
      },
      "hosting.previewFailed",
    ),
  ).toBe(
    "This hosting link could not be checked. Check the link and try again.",
  );
});

test("preview presents the host address, advertised lifetimes and attachment capability", () => {
  const html = renderToStaticMarkup(<HostingPreview host={customHost} />);
  expect(html).toContain("Company");
  expect(html).toContain("https://elo.example.invalid");
  expect(html).toContain("12 hours, 48 hours, No automatic expiry");
  expect(html).toContain("Storage provided by the host");
  expect(html).not.toContain("<input");
});

test("pending creation locks host changes and hides restoration even with an empty catalog", () => {
  const html = renderToStaticMarkup(
    <HostingPicker
      entries={[]}
      selectedId="company"
      onSelect={() => {}}
      status="ready"
      request={vi.fn()}
      refresh={vi.fn()}
      disabled
      pendingCreation
      mobile={false}
    />,
  );
  expect(html).toContain(
    "Continue setting up this Space on its saved hosting.",
  );
  expect(html).toMatch(/id="space-hosting"[^>]*disabled/);
  expect(html).not.toContain("Restore elo.now");
  expect(html).not.toContain("Add hosting or restore elo.now");
});
