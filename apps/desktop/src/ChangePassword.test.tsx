import { beforeEach, expect, test, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { EffectCallback, FormEvent } from "react";
import { ChangePassword } from "./ChangePassword";

const harness = vi.hoisted(() => ({
  values: [] as string[],
  setters: [] as ReturnType<typeof vi.fn>[],
  effects: [] as EffectCallback[],
  submit: undefined as
    ((event: FormEvent<HTMLFormElement>) => void) | undefined,
  change: vi.fn(),
  notify: vi.fn(),
  showError: vi.fn(),
  reportError: vi.fn(),
}));
vi.mock("./biometric", () => ({
  changeProfilePassword: harness.change,
}));
vi.mock("./Toast", () => ({
  useToast: () => ({
    notify: harness.notify,
    showError: harness.showError,
    reportError: harness.reportError,
    onInvalid: vi.fn(),
  }),
}));
vi.mock("react", async (importOriginal) => {
  const original = await importOriginal<typeof import("react")>();
  return {
    ...original,
    // Seed the three form values without a browser. Other hooks still run in
    // React's renderer, including the synchronous duplicate-submit guard.
    useState: (initial: unknown) => {
      const [value, setValue] = original.useState(
        typeof initial === "string"
          ? (harness.values.shift() ?? initial)
          : initial,
      );
      if (typeof initial !== "string") return [value, setValue];
      const setter = vi.fn(setValue);
      harness.setters.push(setter);
      return [value, setter];
    },
    useEffect: (effect: EffectCallback) => harness.effects.push(effect),
  };
});
vi.mock("react/jsx-dev-runtime", async (importOriginal) => {
  const original =
    await importOriginal<typeof import("react/jsx-dev-runtime")>();
  return {
    ...original,
    jsxDEV: (...args: Parameters<typeof original.jsxDEV>) => {
      const element = original.jsxDEV(...args);
      if (element.type === "form")
        harness.submit = (
          element.props as { onSubmit: typeof harness.submit }
        ).onSubmit;
      return element;
    },
  };
});

beforeEach(() => {
  vi.clearAllMocks();
  harness.values = [
    "previous password",
    "different long password",
    "different long password",
  ];
  harness.setters = [];
  harness.effects = [];
  harness.submit = undefined;
  harness.change.mockReset().mockResolvedValue({ biometricNeedsSetup: false });
});

function mount(busy = false) {
  const onBusyChange = vi.fn();
  const onDone = vi.fn();
  const onLockRequired = vi.fn();
  const html = renderToStaticMarkup(
    <ChangePassword
      identity="current-identity"
      busy={busy}
      onBusyChange={onBusyChange}
      onDone={onDone}
      onLockRequired={onLockRequired}
    />,
  );
  const cleanup = harness.effects.map((effect) => effect());
  return {
    html,
    submit: () =>
      harness.submit!({
        preventDefault: vi.fn(),
      } as unknown as FormEvent<HTMLFormElement>),
    dispose: () => cleanup.forEach((stop) => stop?.()),
    onBusyChange,
    onDone,
    onLockRequired,
  };
}

test("current and new credentials are masked and use the shared reveal controls", () => {
  const { html } = mount(true);
  expect(html.match(/type="password"/g)).toHaveLength(3);
  expect(html.match(/aria-label="Show password"/g)).toHaveLength(3);
  expect(html.match(/autoComplete="current-password"/g)).toHaveLength(1);
  expect(html.match(/autoComplete="new-password"/g)).toHaveLength(2);
  expect(html.match(/disabled=""/g)).toHaveLength(7);
});

test.each([
  [
    ["", "different long password", "different long password"],
    "Complete the required field.",
  ],
  [["previous password", "short", "short"], "Use at least 12 characters."],
  [
    ["previous password", "different long password", "another password"],
    "The passwords do not match.",
  ],
  [
    ["previous password", "previous password", "previous password"],
    "Choose a different password.",
  ],
])("invalid input never changes the native profile", (values, expected) => {
  harness.values = values;
  const form = mount();
  form.submit();
  expect(harness.change).not.toHaveBeenCalled();
  expect(harness.showError).toHaveBeenCalledWith(expected);
  expect(form.onBusyChange).not.toHaveBeenCalled();
});

test("a successful mutation is submitted once and clears credentials before leaving", async () => {
  let finish!: (result: { biometricNeedsSetup: boolean }) => void;
  harness.change.mockReturnValue(
    new Promise((resolve) => {
      finish = resolve;
    }),
  );
  const form = mount();
  form.submit();
  form.submit();
  expect(harness.change).toHaveBeenCalledExactlyOnceWith(
    "previous password",
    "different long password",
    "current-identity",
  );
  expect(form.onBusyChange).toHaveBeenCalledWith(true);
  expect(form.onDone).not.toHaveBeenCalled();
  finish({ biometricNeedsSetup: false });
  await vi.waitFor(() => expect(form.onDone).toHaveBeenCalledTimes(1));
  expect(
    harness.setters.every((setter) =>
      setter.mock.calls.some(([value]) => value === ""),
    ),
  ).toBe(true);
  expect(harness.notify).toHaveBeenCalledWith("Password changed.");
  expect(form.onBusyChange).toHaveBeenLastCalledWith(false);
});

test("biometric reenrollment refusal is a successful password change with setup guidance", async () => {
  harness.change.mockResolvedValue({ biometricNeedsSetup: true });
  const form = mount();
  form.submit();
  await vi.waitFor(() => expect(form.onDone).toHaveBeenCalledOnce());
  expect(harness.notify).toHaveBeenCalledWith(
    "Password changed. Enable biometric unlock again in More → Settings → Security.",
  );
  expect(harness.reportError).not.toHaveBeenCalled();
});

test("an incorrect current password keeps the form open and releases its busy state", async () => {
  harness.change.mockRejectedValue("password_change_incorrect");
  const form = mount();
  form.submit();
  await vi.waitFor(() =>
    expect(harness.reportError).toHaveBeenCalledWith(
      "password_change_incorrect",
    ),
  );
  expect(form.onDone).not.toHaveBeenCalled();
  expect(form.onLockRequired).not.toHaveBeenCalled();
  expect(form.onBusyChange).toHaveBeenLastCalledWith(false);
});

test("an interrupted mutation immediately requests the dedicated profile lock", async () => {
  harness.change.mockRejectedValue(
    new Error("password_change_recovery_required"),
  );
  const form = mount();
  form.submit();
  await vi.waitFor(() => expect(form.onLockRequired).toHaveBeenCalledOnce());
  expect(form.onDone).not.toHaveBeenCalled();
  expect(harness.notify).not.toHaveBeenCalled();
  expect(harness.reportError).not.toHaveBeenCalled();
});

test("a form disposed during mutation does not navigate or show a late success", async () => {
  let finish!: (result: { biometricNeedsSetup: boolean }) => void;
  harness.change.mockReturnValue(
    new Promise((resolve) => {
      finish = resolve;
    }),
  );
  const form = mount();
  form.submit();
  form.dispose();
  finish({ biometricNeedsSetup: false });
  await vi.waitFor(() =>
    expect(form.onBusyChange).toHaveBeenLastCalledWith(false),
  );
  expect(form.onDone).not.toHaveBeenCalled();
  expect(harness.notify).not.toHaveBeenCalled();
});

test("another profile operation blocks password mutation", () => {
  const form = mount(true);
  form.submit();
  expect(harness.change).not.toHaveBeenCalled();
});
