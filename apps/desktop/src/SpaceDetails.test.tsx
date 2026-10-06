import { expect, test } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { SpaceDetails } from "./SpaceDetails";
import type { SpaceSummary } from "./model";
import type { SpaceManagement } from "./SpaceRoles";
import { SpaceStorage } from "./SpaceStorage";
import type { MessageLifetime } from "./Hosting";

test("attachment settings use the managed Space capability, independent of the active Space", () => {
  const space = {
    id: "managed-space",
    name: "Managed Space",
    owner: true,
    deletable: true,
    status: "joined",
  } as SpaceSummary;
  const management: SpaceManagement = {
    members: [],
    primary_owner: "another-owner",
    roles_revision: 1,
    attachments: {
      policy: {
        enabled: true,
        max_file_bytes: 1024,
        max_space_bytes: 4096,
        retention: { hours: 24 },
      },
      used_bytes: 0,
      reserved_bytes: 0,
    },
  };
  const render = (available: boolean) =>
    renderToStaticMarkup(
      <SpaceDetails
        identity="owner"
        space={space}
        management={{ ...management, attachment_storage_available: available }}
        onView={() => {}}
        onChanged={async () => {}}
      />,
    );
  const broker = render(true);
  expect(broker).toContain("Checking attachment storage…");
  expect(broker).toMatch(/id="space-attachment-retention"[^>]*disabled/);
  const local = render(false);
  expect(local).not.toContain("Checking attachment storage…");
  expect(local).not.toMatch(/id="space-attachment-retention"[^>]*disabled/);
  expect(local).toContain('value="24" selected=""');
});

test("new message retention policies do not expose the legacy-only maintenance action", () => {
  const render = (lifetime: MessageLifetime) =>
    renderToStaticMarkup(
      <SpaceStorage
        identity="owner"
        space={
          {
            id: "managed-space",
            message_lifetime_seconds: lifetime,
          } as SpaceSummary
        }
      />,
    );
  for (const lifetime of [
    21_600,
    43_200,
    86_400,
    172_800,
    "no_expiry",
  ] as const) {
    expect(render(lifetime)).not.toContain('id="space-storage-days"');
  }
});
