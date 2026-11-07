"use client";

import { useEffect, useState } from "react";
import historyJson from "@/lib/star-history.json";
import {
  chartPoints,
  formatStarCount,
  formatUtcDate,
  formatUtcTimestamp,
  isStarsResponse,
  payloadFromHistory,
  type StarsResponse,
} from "@/lib/stars";

const recorded = payloadFromHistory(historyJson);

function deltaCopy(data: StarsResponse): { text: string; tone: string } {
  const { since, stars } = data.delta;
  if (since === null || stars === null) return { text: `Daily record starts ${formatUtcDate(data.history[0]?.date ?? data.asOf)}.`, tone: "" };
  if (stars === 0) return { text: `Same as ${formatUtcDate(since)}.`, tone: "" };
  if (stars > 0) return { text: `${formatStarCount(stars)} more than ${formatUtcDate(since)}.`, tone: "ecosystem-stars__delta--up" };
  return { text: `${formatStarCount(Math.abs(stars))} fewer than ${formatUtcDate(since)}.`, tone: "ecosystem-stars__delta--down" };
}

function statusCopy(data: StarsResponse): string {
  switch (data.source) {
    case "github":
      return `Updated ${formatUtcTimestamp(data.asOf)} from GitHub.`;
    case "snapshot":
      return data.stale
        ? `Showing the last recorded total from ${formatUtcDate(data.asOf)}. GitHub is unavailable.`
        : `Recorded ${formatUtcDate(data.asOf)}.`;
    default: {
      const unreachable: never = data.source;
      return unreachable;
    }
  }
}

export function EcosystemStarsView({ data }: { data: StarsResponse | null }) {
  if (!data || data.repoCount === 0) {
    return (
      <section className="ecosystem-stars" aria-labelledby="ecosystem-stars-title">
        <p id="ecosystem-stars-title" className="ecosystem-stars__kicker">Ecosystem stars</p>
        <p className="ecosystem-stars__unavailable">GitHub star count is temporarily unavailable.</p>
      </section>
    );
  }

  const delta = deltaCopy(data);
  const points = chartPoints(data.history);
  const chartLabel = points.map((point) => `${formatUtcDate(point.date)}: ${formatStarCount(point.total)}`).join("; ");
  const line = points.map((point) => `${point.x},${point.y}`).join(" ");

  return (
    <section className="ecosystem-stars" aria-labelledby="ecosystem-stars-title">
      <div className="ecosystem-stars__count">
        <p id="ecosystem-stars-title" className="ecosystem-stars__kicker">Ecosystem stars</p>
        <p className="ecosystem-stars__total">
          <span aria-hidden="true">★</span>{" "}
          <span className="ecosystem-stars__number">{formatStarCount(data.total)}</span>
          <span className="ecosystem-stars__sr"> GitHub stars</span>
        </p>
        <p className="ecosystem-stars__scope">across {formatStarCount(data.repoCount)} public repositories</p>
        <p className={`ecosystem-stars__delta ${delta.tone}`}>{delta.text}</p>
      </div>
      <figure className="ecosystem-stars__growth">
        <svg role="img" aria-label={`Star growth. ${chartLabel}.`} viewBox="0 0 320 72" className="ecosystem-stars__chart">
          <polyline points={line} fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
          {points.map((point) => <circle key={point.date} cx={point.x} cy={point.y} r="3.5" />)}
        </svg>
        <figcaption>
          <span>{formatUtcDate(points[0].date)}</span>
          <span>{formatUtcDate(points[points.length - 1].date)}</span>
        </figcaption>
        <p className="ecosystem-stars__asof">{statusCopy(data)}</p>
      </figure>
      <details className="ecosystem-stars__repos">
        <summary>Per repository</summary>
        <ul>
          {data.repos.map((repo) => (
            <li key={repo.fullName}>
              <a href={repo.url}>{repo.name}</a>
              <span>{formatStarCount(repo.stars)} <span className="ecosystem-stars__sr">stars</span></span>
            </li>
          ))}
        </ul>
      </details>
      <p className="ecosystem-stars__api">
        <a href="/api/stars">Star data for agents (JSON)</a>
      </p>
    </section>
  );
}

export function EcosystemStars() {
  const [data, setData] = useState<StarsResponse | null>(recorded);
  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/stars", { signal: controller.signal, headers: { accept: "application/json" }, credentials: "omit" })
      .then(async (response) => {
        if (!response.ok) return;
        const body: unknown = await response.json();
        if (isStarsResponse(body) && body.repoCount > 0) setData(body);
      })
      .catch(() => {});
    return () => controller.abort();
  }, []);
  return <EcosystemStarsView data={data} />;
}
