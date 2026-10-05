import { expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  AttachmentStorageForm,
  attachmentStorageRequest,
  emptyAttachmentStorage,
  saveAttachmentStorage,
  saveAttachmentRetention,
  type AttachmentStorageStatus,
} from "./AttachmentStorageForm";
import { SpaceAttachments } from "./SpaceAttachments";
import type { SpaceSummary } from "./model";

test("attachment setup starts off and exposes only the selected provider's fields", () => {
  const render = (
    enabled = false,
    provider: "mega_folder" | "s3_compatible" = "mega_folder",
  ) =>
    renderToStaticMarkup(
      <AttachmentStorageForm
        value={emptyAttachmentStorage(enabled, provider)}
        onChange={() => {}}
      />,
    );
  const disabled = render();
  expect(disabled).toContain("Enable attachments");
  expect(disabled).not.toContain("checked");
  expect(disabled).not.toContain("<select");
  expect(disabled).not.toContain('type="password"');

  const mega = render(true);
  expect(mega).toContain("MEGA folder link");
  expect(mega).toContain("Folder write access key");
  expect(mega.match(/type="password"/g)).toHaveLength(2);
  expect(mega.match(/autoComplete="off"/g)).toHaveLength(2);
  expect(mega).not.toContain("Endpoint URL");
  expect(mega).not.toContain("Account password</label>");

  const s3 = render(true, "s3_compatible");
  for (const label of [
    "Endpoint URL",
    "Region",
    "Bucket",
    "Access key",
    "Secret key",
  ])
    expect(s3).toContain(label);
  expect(s3).not.toContain("MEGA folder link");
  expect(s3.match(/type="password"/g)).toHaveLength(2);
});

test("requests omit all credentials while off and omit credentials for another provider", () => {
  const draft = {
    ...emptyAttachmentStorage(),
    folder_link: " https://mega.nz/folder/example#key ",
    write_auth: " write-key ",
    endpoint: " https://storage.example ",
    region: " eu-central-1 ",
    bucket: " files ",
    access_key: " access-key ",
    secret_key: " secret-with-significant-spaces ",
  };
  expect(attachmentStorageRequest(draft)).toEqual({ enabled: false });
  expect(attachmentStorageRequest({ ...draft, enabled: true })).toEqual({
    enabled: true,
    provider: "mega_folder",
    folder_link: "https://mega.nz/folder/example#key",
    write_auth: "write-key",
  });
  expect(
    attachmentStorageRequest({
      ...draft,
      enabled: true,
      provider: "s3_compatible",
    }),
  ).toEqual({
    enabled: true,
    provider: "s3_compatible",
    endpoint: "https://storage.example",
    region: "eu-central-1",
    bucket: "files",
    access_key: "access-key",
    secret_key: " secret-with-significant-spaces ",
  });
});

const configured: AttachmentStorageStatus = {
  available: true,
  enabled: true,
  configured: true,
  provider: "mega_folder",
  revision: 4,
  used_bytes: 0,
  max_space_bytes: 50 * 1024 ** 2,
  max_file_bytes: 5 * 1024 ** 2,
  retention_hours: 1,
};

test("saving sends the current revision and requires a confirmed provider status", async () => {
  const request = vi
    .fn<(_op: string, _body?: object) => Promise<AttachmentStorageStatus>>()
    .mockResolvedValue(configured);
  const draft = {
    ...emptyAttachmentStorage(true),
    folder_link: "folder",
    write_auth: "key",
  };
  await expect(saveAttachmentStorage(draft, 3, request)).resolves.toEqual(
    configured,
  );
  expect(request.mock.calls).toEqual([
    [
      "space_external_storage_configure",
      {
        enabled: true,
        provider: "mega_folder",
        folder_link: "folder",
        write_auth: "key",
        expected_revision: 3,
        retention_hours: 1,
      },
    ],
    ["space_external_storage_status"],
  ]);
  for (const status of [
    { ...configured, enabled: false },
    { ...configured, configured: false },
    { ...configured, available: false },
    { ...configured, provider: "s3_compatible" as const },
    { ...configured, retention_hours: null },
    { ...configured, retention_hours: 12 },
  ]) {
    request.mockResolvedValue(status);
    await expect(saveAttachmentStorage(draft, 3, request)).rejects.toThrow(
      "has not been confirmed",
    );
  }
});

test("changing provider preserves the owner's selected retention", async () => {
  const status = { ...configured, retention_hours: 12 };
  const request = vi
    .fn<(_op: string, _body?: object) => Promise<AttachmentStorageStatus>>()
    .mockResolvedValue(status);
  await expect(
    saveAttachmentStorage(emptyAttachmentStorage(true), 3, request, 12),
  ).resolves.toEqual(status);
  expect(request.mock.calls[0][1]).toMatchObject({
    expected_revision: 3,
    retention_hours: 12,
  });
});

test("retention changes use the broker revision and require the confirmed owner policy", async () => {
  const updated = { ...configured, revision: 5, retention_hours: 12 };
  const request = vi
    .fn<(_op: string, _body?: object) => Promise<AttachmentStorageStatus>>()
    .mockResolvedValue(updated);
  await expect(
    saveAttachmentRetention(12, configured, request),
  ).resolves.toEqual(updated);
  expect(request.mock.calls).toEqual([
    ["space_attachment_retention", { hours: 12, expected_revision: 4 }],
    ["space_external_storage_status"],
  ]);
  request.mockClear().mockResolvedValue(configured);
  await expect(
    saveAttachmentRetention(12, configured, request),
  ).rejects.toThrow("Invalid attachment storage response");
  expect(request).toHaveBeenCalledTimes(2);
  request.mockClear().mockRejectedValue(new Error("Configuration changed"));
  await expect(
    saveAttachmentRetention(12, configured, request),
  ).rejects.toThrow("Configuration changed");
  expect(request).toHaveBeenCalledTimes(1);
});

test("a migrated configuration can receive an explicit one-hour owner policy", async () => {
  const legacy = { ...configured, enabled: false, retention_hours: null };
  const updated = { ...configured, revision: 5 };
  const request = vi
    .fn<(_op: string, _body?: object) => Promise<AttachmentStorageStatus>>()
    .mockResolvedValue(updated);
  await expect(saveAttachmentRetention(1, legacy, request)).resolves.toEqual(
    updated,
  );
  expect(request.mock.calls[0]).toEqual([
    "space_attachment_retention",
    { hours: 1, expected_revision: 4 },
  ]);
});

test("a failed provider test cannot become a successful save or retry automatically", async () => {
  const request = vi
    .fn<(_op: string, _body?: object) => Promise<AttachmentStorageStatus>>()
    .mockRejectedValue(new Error("Provider rejected credentials"));
  await expect(
    saveAttachmentStorage(emptyAttachmentStorage(true), 3, request),
  ).rejects.toThrow("Provider rejected credentials");
  expect(request).toHaveBeenCalledTimes(1);
  expect(request.mock.calls[0][0]).toBe("space_external_storage_configure");
});

test("disabling submits no credentials and verifies that new uploads are off", async () => {
  const disabled = { ...configured, enabled: false };
  const request = vi
    .fn<(_op: string, _body?: object) => Promise<AttachmentStorageStatus>>()
    .mockResolvedValue(disabled);
  await expect(
    saveAttachmentStorage(
      { ...emptyAttachmentStorage(), write_auth: "discarded" },
      4,
      request,
    ),
  ).resolves.toEqual(disabled);
  expect(request.mock.calls[0]).toEqual([
    "space_external_storage_disable",
    { enabled: false, expected_revision: 4 },
  ]);
});

test("owner attachment settings are hidden without the configured broker capability", () => {
  const render = (owner: boolean, storageAvailable: boolean) =>
    renderToStaticMarkup(
      <SpaceAttachments
        identity="owner"
        space={{ id: "space", owner } as SpaceSummary}
        storageAvailable={storageAvailable}
        value={{
          policy: {
            enabled: false,
            max_file_bytes: 5_000_000,
            max_space_bytes: 50_000_000,
            retention: { hours: 24 },
          },
          used_bytes: 0,
          reserved_bytes: 0,
        }}
        onChanged={async () => {}}
      />,
    );
  expect(render(true, true)).toContain("Checking attachment storage");
  expect(render(true, true)).not.toContain("Preview attachment cleanup");
  expect(render(true, false)).toContain("Preview attachment cleanup");
  expect(render(true, false)).not.toContain("Checking attachment storage");
  expect(render(false, true)).not.toContain("Checking attachment storage");
});
