import { useEffect, useState } from "react";
import { apiUrl, getReplay } from "./api";
import type { LoopEvent } from "./types";

export type Source = { mode: "live" | "replay"; loopId: string; speed: number } | null;

/** Live: EventSource (server replays history first, so reconnecting loses nothing). Replay: stored events, timed. */
export function useEvents(source: Source): { events: LoopEvent[]; error: string } {
  const [events, setEvents] = useState<LoopEvent[]>([]);
  const [error, setError] = useState("");
  const key = source ? `${source.mode}:${source.loopId}:${source.speed}` : "";

  useEffect(() => {
    setEvents([]);
    setError("");
    if (!source) return;
    let closed = false;
    let timer: number | undefined;
    let es: EventSource | undefined;

    if (source.mode === "live") {
      es = new EventSource(apiUrl(`/loop/${source.loopId}/events`));
      es.onmessage = (m) => {
        const e: LoopEvent = JSON.parse(m.data);
        setEvents((prev) => (prev.some((p) => p.seq === e.seq) ? prev : [...prev, e]));
        if (e.type === "done") es?.close();
      };
      es.onerror = () => { if (!closed) setError(es?.readyState === EventSource.CLOSED ? "stream closed by server" : "stream interrupted, reconnecting…"); };
      es.onopen = () => setError("");
    } else {
      getReplay(source.loopId).then((all) => {
        let i = 0;
        timer = window.setInterval(() => {
          if (closed) return;
          i += 1;
          setEvents(all.slice(0, i));
          if (i >= all.length) window.clearInterval(timer);
        }, Math.max(15, 450 / source.speed));
      }).catch((e) => setError(e instanceof Error ? e.message : String(e)));
    }
    return () => { closed = true; es?.close(); if (timer) window.clearInterval(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  return { events, error };
}
