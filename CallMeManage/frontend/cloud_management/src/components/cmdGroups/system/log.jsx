import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import { getDeviceAccessLog } from "../../../api/api_devices";
import { formatDate } from "../../../utils/formatDate";
import DismissibleError from "../../DismissibleError";
import { Pagination } from "../../Pagination";
import { Reload_Result } from "../../commandResult/reload_command_result";

const ACCESS_LOG_PAGE_SIZE = 40;

function navReducer(state, action) {
  switch (action.type) {
    case "reset":
      return { stack: [], index: 0 };
    case "set_page": {
      const stack = state.stack.slice(0, action.index);
      stack[action.index] = action.page;
      return { stack, index: action.index };
    }
    case "go_to_index":
      return { ...state, index: action.index };
    default:
      return state;
  }
}

function TimeCell({ value }) {
  return (
    <>
      <div style={{ fontWeight: 500 }}>{formatDate(value)}</div>
      <div style={{ fontSize: "0.75rem", opacity: 0.7, marginTop: "2px" }}>
        {value ? new Date(value).toLocaleString("en-US") : "-"}
      </div>
    </>
  );
}

export default function AccessLog({ devId }) {
  const [nav, dispatch] = useReducer(navReducer, { stack: [], index: 0 });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const cancelledRef = useRef(false);
  const prefetchRef = useRef(null);

  const currentPage = nav.stack[nav.index] || null;
  const data = currentPage?.items ?? null;

  const fetchPage = useCallback(async (afterAccId) => {
    const result = await getDeviceAccessLog(devId, afterAccId);
    return { items: result.items || [], hasNext: Boolean(result.has_next) };
  }, [devId]);

  const prefetchNext = useCallback((page) => {
    if (!page?.hasNext || page.items.length === 0) return;
    const afterAccId = page.items[page.items.length - 1].acc_id;
    if (prefetchRef.current?.afterAccId === afterAccId) return;
    prefetchRef.current = {
      afterAccId,
      promise: fetchPage(afterAccId).catch(() => null),
    };
  }, [fetchPage]);

  const loadFirstPage = useCallback(async () => {
    setLoading(true);
    setError("");
    prefetchRef.current = null;
    try {
      const page = await fetchPage(null);
      if (cancelledRef.current) return;
      dispatch({ type: "set_page", index: 0, page });
      prefetchNext(page);
    } catch (err) {
      if (!cancelledRef.current) setError(err.detail || "Failed to load system access log");
    } finally {
      if (!cancelledRef.current) setLoading(false);
    }
  }, [fetchPage, prefetchNext]);

  useEffect(() => {
    cancelledRef.current = false;
    prefetchRef.current = null;
    dispatch({ type: "reset" });
    if (devId) loadFirstPage();
    return () => {
      cancelledRef.current = true;
    };
  }, [devId, loadFirstPage]);

  async function goNext() {
    const nextIndex = nav.index + 1;
    if (nextIndex < nav.stack.length) {
      dispatch({ type: "go_to_index", index: nextIndex });
      return;
    }
    if (!currentPage?.hasNext || currentPage.items.length === 0) return;
    const afterAccId = currentPage.items[currentPage.items.length - 1].acc_id;
    setLoading(true);
    setError("");
    try {
      let page = prefetchRef.current?.afterAccId === afterAccId
        ? await prefetchRef.current.promise
        : null;
      if (!page) page = await fetchPage(afterAccId);
      if (cancelledRef.current) return;
      dispatch({ type: "set_page", index: nextIndex, page });
      prefetchRef.current = null;
      prefetchNext(page);
    } catch (err) {
      if (!cancelledRef.current) setError(err.detail || "Failed to load system access log");
    } finally {
      if (!cancelledRef.current) setLoading(false);
    }
  }

  function goPrev() {
    if (nav.index > 0) dispatch({ type: "go_to_index", index: nav.index - 1 });
  }

  const pagination = (
    <Pagination
      hasPrev={nav.index > 0}
      hasNext={!loading && Boolean(currentPage?.hasNext)}
      onPrev={goPrev}
      onNext={goNext}
    />
  );
  const rowOffset = nav.index * ACCESS_LOG_PAGE_SIZE;

  return (
    <div className="command-configuration">
      <div className="command-output">
        <div className="command-output-title" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
          <h3 style={{ margin: 0, fontSize: "1.1rem", fontWeight: 600 }}>System Access Log</h3>
          <Reload_Result loading={loading} onRefresh={loadFirstPage} />
        </div>

        {error && <DismissibleError message={error} onDismiss={() => setError("")} />}
        <div style={{ margin: "1rem 0" }}>{pagination}</div>

        {loading && !data ? (
          <div className="center-loading">Fetching system access log...</div>
        ) : data?.length ? (
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: "8%" }}>No</th>
                <th style={{ width: "24%" }}>User</th>
                <th style={{ width: "34%" }}>Access Time</th>
                <th style={{ width: "34%" }}>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {data.map((row, index) => (
                <tr key={row.acc_id}>
                  <td>{rowOffset + index + 1}</td>
                  <td>{row.usr_name || "Unknown user"}</td>
                  <td><TimeCell value={row.acc_date} /></td>
                  <td><TimeCell value={row.acc_lastseen} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="config-placeholder">
            {nav.index > 0
              ? 'No more access logs on this page. Click "←" to go back.'
              : "No system access log on this device yet"}
          </div>
        )}

        <div style={{ margin: "1rem 0" }}>{pagination}</div>
      </div>
    </div>
  );
}
