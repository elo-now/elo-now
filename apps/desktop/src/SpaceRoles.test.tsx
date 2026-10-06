import { expect, test } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  SpaceMembers,
  SpaceRoleRequests,
  type SpaceManagement,
} from "./SpaceRoles";
import type { SpaceSummary, View } from "./model";
import { presentError } from "./errors";
import { en } from "./locales/en";

const management: SpaceManagement = {
  primary_owner: "creator",
  roles_revision: 1,
  members: [
    { identity: "creator", name: "Creator", role: "primary_owner" },
    { identity: "owner", name: "Co-owner", role: "owner" },
    { identity: "member", name: "Member", role: "member" },
  ],
};

test("co-owners have actions for ordinary members but not other owners", () => {
  const render = (identity: string) =>
    renderToStaticMarkup(
      <SpaceMembers
        identity={identity}
        space={{ id: "space" } as SpaceSummary}
        management={management}
        onChanged={async () => {}}
        onView={() => {}}
      />,
    );
  const coOwner = render("owner");
  const primary = render("creator");
  const action = (name: string) =>
    en["spaces.memberActions"].replace("{name}", name);
  expect(coOwner).toContain(action("Member"));
  expect(coOwner).not.toContain(action("Co-owner"));
  expect(coOwner).not.toContain(action("Creator"));
  expect(primary).toContain(action("Co-owner"));
  expect(primary).toContain(action("Member"));
  expect(primary).not.toContain(action("Creator"));
});

test("a retained primary transfer request can be declined but cannot be accepted", () => {
  const html = renderToStaticMarkup(
    <SpaceRoleRequests
      view={
        {
          identity: "owner",
          space_role_requests: [
            {
              space_id: "space",
              space_name: "Team",
              revision: 2,
              request: {
                id: "old-request",
                kind: "transfer_primary",
                target: "owner",
                target_name: "Co-owner",
                requester: "creator",
                requester_name: "Creator",
                created_at: 1,
              },
            },
          ],
        } as View
      }
      onView={() => {}}
    />,
  );
  expect(html).toContain("Primary ownership cannot be transferred");
  expect(html).toContain(en["spaces.decline"]);
  expect(html).not.toContain(`>${en["spaces.approve"]}<`);
  expect(html).not.toContain("Contact email");
});

test.each([
  [
    "Only the primary owner can change Space owners.",
    "error.spaceOwnersPrimaryOnly",
  ],
  ["The primary owner cannot be removed.", "error.spacePrimaryProtected"],
  ["Primary ownership cannot be transferred.", "error.spacePrimaryFixed"],
] as const)(
  "presents the ownership denial without a generic retry: %s",
  (message, key) => {
    expect(presentError(message).message).toBe(en[key]);
  },
);

test.each(["owner", "primary_owner"] as const)(
  "only the primary owner can accept a retained owner removal: %s",
  (role) => {
    const html = renderToStaticMarkup(
      <SpaceRoleRequests
        view={
          {
            identity: role === "owner" ? "owner" : "creator",
            spaces: [{ id: "space", role }],
            space_role_requests: [
              {
                space_id: "space",
                space_name: "Team",
                revision: 2,
                request: {
                  id: "old-removal",
                  kind: "remove_owner",
                  target: "owner",
                  target_name: "Co-owner",
                  requester: "creator",
                  requester_name: "Creator",
                  created_at: 1,
                },
              },
            ],
          } as View
        }
        onView={() => {}}
      />,
    );
    expect(html).toContain(en["spaces.decline"]);
    expect(html.includes(`>${en["spaces.approve"]}<`)).toBe(
      role === "primary_owner",
    );
  },
);
