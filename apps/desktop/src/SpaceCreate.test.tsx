import { beforeEach, expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { invoke } from "@tauri-apps/api/core";
import type { FormEventHandler } from "react";
import { SpaceCreate } from "./SpaceCreate";
import { presentError } from "./errors";
import { en } from "./locales/en";
import type { View } from "./model";
import type { HostingProfileSummary } from "./Hosting";

const catalog = vi.hoisted(() => ({
  entries: [] as HostingProfileSummary[],
  status: "ready" as "loading" | "ready" | "failed",
  request: vi.fn(),
  refresh: vi.fn(),
}));
const submission = vi.hoisted(() => ({
  submit: undefined as FormEventHandler<HTMLFormElement> | undefined,
  reportError: vi.fn(),
  showError: vi.fn(),
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("./Toast", () => ({
  useToast: () => ({
    reportError: submission.reportError,
    showError: submission.showError,
    onInvalid: vi.fn(),
  }),
}));
vi.mock("react/jsx-dev-runtime", async (importOriginal) => {
  const original =
    await importOriginal<typeof import("react/jsx-dev-runtime")>();
  return {
    ...original,
    jsxDEV: (...args: Parameters<typeof original.jsxDEV>) => {
      const element = original.jsxDEV(...args);
      const props = element.props as {
        className?: string;
        onSubmit?: FormEventHandler<HTMLFormElement>;
      };
      if (element.type === "form" && props.className === "space-create-form")
        submission.submit = props.onSubmit;
      return element;
    },
  };
});
vi.mock("./Hosting", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./Hosting")>()),
  useHostingCatalog: () => catalog,
}));

vi.mock("./InvitationFlow", () => ({
  InvitationCode: () => <div>Invitation QR</div>,
}));

beforeEach(() => {
  submission.submit = undefined;
  submission.reportError.mockReset();
  submission.showError.mockReset();
  vi.mocked(invoke).mockReset();
});

function render(
  creation: View["space_creation"],
  mobile: boolean,
  storageAvailable = false,
  hosts?: HostingProfileSummary[],
) {
  catalog.entries = hosts ?? [
    {
      id: "elo.now",
      name: "elo.now",
      url: "https://elo.example.invalid",
      message_lifetimes: [21_600, 43_200, 86_400],
      default_message_lifetime: 86_400,
      attachment_storage_available: storageAvailable,
      attachment_storage_managed: false,
      builtin: true,
    },
  ];
  catalog.status = "ready";
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

const managedHost: HostingProfileSummary = {
  id: "company",
  name: "Company",
  url: "https://company.example.invalid",
  message_lifetimes: [172_800, "no_expiry"],
  default_message_lifetime: "no_expiry",
  attachment_storage_available: true,
  attachment_storage_managed: true,
  builtin: false,
  storage_provider: "s3",
};

test("creation uses the selected hosting's lifetimes and managed attachments without credential fields", () => {
  const html = render(null, true, false, [managedHost]);
  expect(html).toContain('value="172800"');
  expect(html).toContain('value="no_expiry" selected=""');
  expect(html).not.toContain('value="21600"');
  expect(html).toContain(
    "Attachments are enabled using storage provided by this host.",
  );
  expect(html).not.toContain("Enable attachments");
  expect(html).not.toContain('type="password"');
  expect(html).not.toContain("150 MB");
});

test("an empty catalog does not silently recreate elo.now and offers an explicit restore", () => {
  const html = render(null, false, true, []);
  expect(html).toContain("Add hosting or restore elo.now to create a Space.");
  expect(html).toContain("Restore elo.now");
  expect(html).not.toContain('<option value="elo.now"');
  expect(html).toMatch(/type="submit"[^>]*disabled/);
  expect(html).not.toContain("Enable attachments");
});

test("resuming keeps the saved host and lifetime even when its catalog entry was removed", () => {
  const html = render(
    {
      name: "Existing Space",
      hosting_id: managedHost.id,
      message_lifetime_seconds: "no_expiry",
      attachment_storage_pending: true,
      attachment_storage_managed: true,
    },
    true,
    false,
    [],
  );
  expect(html).toContain("Saved hosting");
  expect(html).toContain('value="no_expiry" selected=""');
  expect(html).toContain("storage provided by this host");
  expect(html).not.toContain("Restore elo.now");
  expect(html).not.toContain('type="password"');
  expect(html).not.toMatch(/type="submit"[^>]*disabled/);
});

test.each([
  ["Space server timed out.", "error.serverTimeout"],
  ["Space access denied.", "error.replicaAccess"],
  ["Hosting capacity reached.", "error.hostingCapacity"],
  [
    "Could not contact attachment storage. Try again.",
    "spaces.attachments.loadFailed",
  ],
  [
    "Could not configure attachment storage. Check the details and try again.",
    "spaces.attachments.saveFailed",
  ],
  [
    {
      message: "unexpected response containing fixture-secret",
      url: "https://fixture.invalid/private",
    },
    "error.generic",
  ],
] as const)(
  "attachment-enabled creation preserves the safe explanation for %j",
  async (error, key) => {
    for (const creation of [
      null,
      {
        name: "Saved Space",
        hosting_id: managedHost.id,
        attachment_storage_pending: true,
      },
    ]) {
      submission.reportError.mockClear();
      submission.showError.mockClear();
      vi.mocked(invoke)
        .mockReset()
        .mockRejectedValueOnce(error)
        .mockResolvedValue({ view: {} });
      render(creation, true, false, [managedHost]);
      expect(submission.submit).toBeTypeOf("function");
      const preventDefault = vi.fn();
      submission.submit!({ preventDefault } as unknown as Parameters<
        FormEventHandler<HTMLFormElement>
      >[0]);
      await vi.waitFor(() =>
        expect(submission.reportError).toHaveBeenCalledExactlyOnceWith(error),
      );
      expect(preventDefault).toHaveBeenCalledOnce();
      expect(submission.showError).not.toHaveBeenCalled();
      expect(presentError(submission.reportError.mock.calls[0][0])).toEqual({
        message: en[key],
      });
      expect(invoke).toHaveBeenNthCalledWith(1, "operate", {
        request: expect.objectContaining({
          op: "space_create",
          attachment_storage: { enabled: true, managed: true },
        }),
      });
      expect(invoke).toHaveBeenNthCalledWith(2, "operate", {
        request: { op: "space_list", expected_identity: "owner" },
      });
    }
  },
);
