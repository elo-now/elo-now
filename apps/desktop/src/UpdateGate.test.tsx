import { afterEach, expect, test } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { UpdateBanner, UpdateGate } from "./UpdateGate";
import { setUpdateRequired, subscribeUpdateRequired } from "./releasePolicy";

afterEach(() => setUpdateRequired(false));

test("local content is available before discovery and while an update is required", () => {
  for (const required of [false, true]) {
    setUpdateRequired(required);
    const html = renderToStaticMarkup(
      <UpdateGate>
        <main>
          <UpdateBanner />
          <p>Saved messages</p>
        </main>
      </UpdateGate>,
    );
    expect(html).toContain("Saved messages");
    expect(html.includes("Update required to go online.")).toBe(required);
    expect(html).not.toContain("Checking for updates");
    expect(html).not.toContain("<button");
  }
});

test("unchanged background policy does not trigger repeated UI updates", () => {
  let changes = 0;
  const unsubscribe = subscribeUpdateRequired(() => changes++);
  setUpdateRequired(true);
  setUpdateRequired(true);
  expect(changes).toBe(1);
  setUpdateRequired(false);
  expect(changes).toBe(2);
  unsubscribe();
  setUpdateRequired(true);
  expect(changes).toBe(2);
});
