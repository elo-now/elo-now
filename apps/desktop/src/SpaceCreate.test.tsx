import { expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { SpaceCreate } from "./SpaceCreate";
import type { View } from "./model";

vi.mock("./InvitationFlow", () => ({
  InvitationCode: () => <div>Invitation QR</div>,
}));

function render(creation: View["space_creation"], mobile: boolean) {
  return renderToStaticMarkup(
    <SpaceCreate
      view={{ identity: "owner", space_creation: creation } as View}
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
