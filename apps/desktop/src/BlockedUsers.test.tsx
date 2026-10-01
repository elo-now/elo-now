import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { BlockingProvider, BlockUserAction, BlockedUsers } from "./BlockedUsers";
import { t } from "./i18n";
import type { View } from "./model";

const view = {
  identity: "me",
  streams: [{
    is_general: true,
    controller: "service-key",
    members: [{ identity_id: "service", credential_ids: ["service-key"] }],
  }],
} as unknown as View;

it("hides service blocking actions while allowing an ordinary person with the same name", () => {
  const render = (identity: string) => renderToStaticMarkup(
    <BlockingProvider view={view} onChange={async () => {}}>
      <BlockUserAction identity={identity} name="elo.now" />
    </BlockingProvider>,
  );
  expect(render("service")).toBe("");
  expect(render("person")).toContain(t("blocking.block"));
});

it("allows an old service block to be removed instead of trapping it invisibly", () => {
  const blocked = {
    ...view,
    blocked_users: [{ identity: "service", name: "elo.now" }],
  };
  const html = renderToStaticMarkup(
    <BlockingProvider view={blocked} onChange={async () => {}}>
      <BlockedUsers view={blocked} />
    </BlockingProvider>,
  );
  expect(html).toContain(t("blocking.unblockAction"));
  expect(html).not.toContain(t("blocking.blockName", { name: "elo.now" }));
});
