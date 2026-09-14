import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { FloatingSearch } from "./Search";
import { t, locale } from "./i18n";
import { useToast } from "./Toast";
import type { SpaceSummary, View } from "./model";
import "./spaces.css";

type JoinRequest = { id: string; name: string };
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
    entry.name.toLocaleLowerCase(locale).includes(needle),
  );
  const count = new Intl.NumberFormat(locale).format(
    requests?.length ?? space.requests,
  );
  const blocked = loading || deciding !== undefined;
  return (
    <section
      className="space-join-requests"
      aria-label={t("spaces.joinRequests", { count })}
    >
      <h3>{t("spaces.joinRequests", { count })}</h3>
      {loading && requests === undefined && (
        <p className="muted" role="status">
          {t("spaces.loadingRequests")}
        </p>
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
      {requests !== undefined && !failed && !matches.length && (
        <p className="muted">
          {t(needle ? "spaces.noMatchingRequests" : "spaces.noRequests")}
        </p>
      )}
      <ul className="space-requests-list">
        {matches.slice(0, visible).map((entry) => (
          <li
            className="space-request"
            key={entry.id}
            aria-busy={deciding === entry.id}
          >
            <p>{entry.name}</p>
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
    </section>
  );
}
