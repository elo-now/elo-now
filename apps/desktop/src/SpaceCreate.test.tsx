import { expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { SpaceCreate } from "./SpaceCreate";
import type { View } from "./model";

vi.mock("./InvitationFlow", () => ({
  InvitationCode: () => <div>Invitation QR</div>,
}));

function render(
  creation: View["space_creation"],
  mobile: boolean,
  storageAvailable = false,
) {
  return renderToStaticMarkup(
    <SpaceCreate
      view={
        {
          identity: "owner",
          space_creation: creation,
          attachment_storage_available: storageAvailable,
        } as View
      }
      mobile={mobile}
      onView={() => {}}
      onBack={() => {}}
    />,
  );
}

test("creation defaults to approval and resumes the saved choice on every platform", () => {
  for (const mobile of [false, true]) {
    expect(render(null, mobile)).toMatch(/type="checkbox"[^>]*checked/);
    const html = render({ name: "Friends", require_approval: false }, mobile);
    expect(html).toContain("Require owner approval");
    expect(html).toMatch(/type="checkbox"[^>]*disabled/);
    expect(html).not.toMatch(/type="checkbox"[^>]*checked/);
  }
});

test("creating a Space offers attachments only when a broker is configured and starts with uploads off", () => {
  for (const mobile of [false, true]) {
    expect(render(null, mobile)).not.toContain("Enable attachments");
    const html = render(null, mobile, true);
    expect(html).toContain("Enable attachments");
    expect(html.match(/checked=""/g)).toHaveLength(1);
    expect(html).not.toContain("MEGA folder link");
    expect(html).toContain(
      "Attachments are off unless you connect your own storage",
    );
  }
});

test("unfinished attachment setup shows a retry on the saved Space instead of a ready invitation", () => {
  const html = render(
    {
      name: "Friends",
      space: "already-created-space",
      invitation: "must-not-display-yet",
      attachment_storage_pending: true,
    },
    true,
    true,
  );
  expect(html).toContain(
    "Your Space is saved, but attachment setup is unfinished",
  );
  expect(html).toContain("Continue creating your Space");
  expect(html).toContain("MEGA folder link");
  expect(html).not.toContain("Invitation QR");
  expect(html).not.toContain("Your Space is ready");
});

test("the first invitation explains its actual admission policy", () => {
  for (const mobile of [false, true]) {
    for (const require_approval of [true, false]) {
      const html = render(
        { name: "Friends", invitation: "test-link", require_approval },
        mobile,
      );
      expect(html.includes("requires your approval")).toBe(require_approval);
      expect(html.includes("join without your approval")).toBe(
        !require_approval,
      );
      expect(html).toContain("24 hours");
    }
  }
});
