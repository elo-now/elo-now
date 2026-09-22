import { useDesktopLayout } from "./PageSurface";
import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { FloatingSearch, SearchField } from "./Search";
import { t, locale } from "./i18n";
import { useToast } from "./Toast";
import type { SpaceSummary, View } from "./model";
import "./spaces.css";

type JoinRequest = {
  id: string;
  identity: string;
  name: string;
  note?: string;
};
type Reply = { view: View; result?: { requests?: JoinRequest[] } };
const batchSize = 20;

/** Owner decisions stay bound to the selected Space, including delayed replies. */
export function SpaceJoinRequests({
  identity,
  space,
  refresh,
  onView,
}: {
  identity: string;
  space: SpaceSummary;
  refresh: number;
  onView: (view: View) => void;
}) {
  const desktop = useDesktopLayout();
  const { reportError } = useToast();
  const [requests, setRequests] = useState<JoinRequest[]>();
  const [query, setQuery] = useState("");
  const [visible, setVisible] = useState(batchSize);
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);
  const [deciding, setDeciding] = useState<string>();
  const mounted = useRef(false);
  const running = useRef(false);
  const updateView = useRef(onView);
  updateView.current = onView;
  const call = (op: string, body: Record<string, unknown>) =>
    invoke<Reply>("operate", {
      request: {
        op,
        id: space.id,
        body,
        expected_identity: identity,
        expected_space: space.id,
      },
    });
  const reload = async () => {
    const result = await call("space_manage", {});
    if (!mounted.current) return;
    setRequests(result.result?.requests ?? []);
    setFailed(false);
    updateView.current(result.view);
  };
  const load = async () => {
    if (running.current) return;
    running.current = true;
    setLoading(true);
    try {
      await reload();
    } catch (error) {
      if (mounted.current) {
        setFailed(true);
        reportError(error);
      }
    } finally {
      running.current = false;
      if (mounted.current) setLoading(false);
    }
  };
  const loadRef = useRef(load);
  loadRef.current = load;
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  useEffect(() => {
    void loadRef.current();
  }, [space.requests, refresh]);
  const decide = async (entry: JoinRequest, approve: boolean) => {
    if (running.current) return;
    running.current = true;
    setDeciding(entry.id);
    try {
      const result = await call("space_decide", { id: entry.id, approve });
      if (!mounted.current) return;
      // Remove only after the server confirms this exact decision.
      setRequests((previous) => previous?.filter((row) => row.id !== entry.id));
      updateView.current(result.view);
      await reload();
    } catch (error) {
      if (mounted.current) {
        setFailed(true);
        reportError(error);
      }
    } finally {
      running.current = false;
      if (mounted.current) setDeciding(undefined);
    }
  };
  const needle = query.trim().toLocaleLowerCase(locale);
  const matches = (requests ?? []).filter((entry) =>
    [entry.name, entry.note ?? "", entry.identity]
      .join(" ")
      .toLocaleLowerCase(locale)
      .includes(needle),
  );
  const total = requests?.length ?? space.requests;
  const count = new Intl.NumberFormat(locale).format(total);
  const empty = requests !== undefined && !failed && requests.length === 0;
  const initialLoading = requests === undefined && !failed;
  const blocked = loading || deciding !== undefined;
  return (
    <section
      className="space-join-requests"
      aria-label={t(empty ? "spaces.noRequests" : "spaces.joinRequests", {
        count,
      })}
    >
      {(initialLoading || empty || total > 0) && (
        <h3 role={initialLoading ? "status" : undefined}>
          {t(
            initialLoading
              ? "spaces.loadingRequests"
              : empty
                ? "spaces.noRequests"
                : "spaces.joinRequests",
            { count },
          )}
        </h3>
      )}
      {failed && (
        <button
          className="secondary"
          disabled={blocked}
          onClick={() => void load()}
        >
          {t("spaces.retryRequests")}
        </button>
      )}
      {!!requests?.length && !failed && !matches.length && (
        <p className="muted">{t("spaces.noMatchingRequests")}</p>
      )}
      {desktop && !!requests?.length && (
        <SearchField
          label={t("spaces.searchRequests")}
          value={query}
          onChange={(value) => {
            setQuery(value);
            setVisible(batchSize);
          }}
        />
      )}
      <ul className="space-requests-list">
        {matches.slice(0, visible).map((entry) => (
          <li
            className="space-request"
            key={entry.id}
            aria-busy={deciding === entry.id}
          >
            <p>
              <strong>{entry.name}</strong>
            </p>
            {entry.note && <p className="space-applicant-note">{entry.note}</p>}
            <div className="space-choice">
              {[true, false].map((approve) => (
                <button
                  key={String(approve)}
                  className={approve ? "" : "secondary"}
                  disabled={blocked}
                  aria-label={t(
                    approve ? "spaces.approveNamed" : "spaces.declineNamed",
                    { name: entry.name },
                  )}
                  onClick={() => void decide(entry, approve)}
                >
                  {t(approve ? "spaces.approve" : "spaces.decline")}
                </button>
              ))}
            </div>
          </li>
        ))}
      </ul>
      {matches.length > visible && (
        <button
          className="secondary"
          disabled={blocked}
          onClick={() => setVisible((value) => value + batchSize)}
        >
          {t("spaces.moreRequests")}
        </button>
      )}
      {!desktop && (
        <div className="invitation-search-layer">
          <FloatingSearch
            label={t("spaces.searchRequests")}
            value={query}
            onChange={(value) => {
              setQuery(value);
              setVisible(batchSize);
            }}
          />
        </div>
      )}
    </section>
  );
}
