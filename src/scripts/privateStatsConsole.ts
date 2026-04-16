import { createSolveStorageKey, listSolveEntries, writeSolveRecord, type SolveEntry, type SolveRecord } from "../utils/solveTracker";

interface ChallengeMeta {
  collection: string;
  slug: string;
  title: string;
  difficulty: string;
  order: number;
  path: string;
}

interface CollectionMeta {
  slug: string;
  title: string;
  path: string;
}

interface StatsConfig {
  challenges: ChallengeMeta[];
  collections: CollectionMeta[];
}

interface ExportPayload {
  version: 1;
  exportedAt: string;
  entries: Array<{
    collection: string;
    challenge: string;
    record: SolveRecord;
  }>;
}

const root = document.querySelector("[data-private-stats]");
const configNode = document.querySelector("#private-stats-config");

if (!(root instanceof HTMLElement) || !(configNode instanceof HTMLScriptElement)) {
  // No-op outside the hidden stats route.
} else {
  const config = JSON.parse(configNode.textContent ?? "{}") as StatsConfig;
  const challengeMap = new Map(config.challenges.map((challenge) => [`${challenge.collection}:${challenge.slug}`, challenge]));
  const collectionMap = new Map(config.collections.map((collection) => [collection.slug, collection]));
  const collectionProgressRoot = root.querySelector("[data-collection-progress]");
  const recentSolvesRoot = root.querySelector("[data-recent-solves]");
  const statusNode = root.querySelector("[data-private-stats-status]");
  const exportButton = root.querySelector("[data-progress-export]");
  const importButton = root.querySelector("[data-progress-import]");
  const importInput = root.querySelector("[data-progress-import-input]");
  const resetButton = root.querySelector("[data-progress-reset]");

  const metricNodes = {
    solvedCount: root.querySelector("[data-private-stat='solvedCount']"),
    completionRate: root.querySelector("[data-private-stat='completionRate']"),
    collectionCount: root.querySelector("[data-private-stat='collectionCount']"),
    attemptCount: root.querySelector("[data-private-stat='attemptCount']")
  };

  const dateFormatter = new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  });

  const setStatus = (message: string) => {
    if (statusNode instanceof HTMLElement) {
      statusNode.textContent = message;
    }
  };

  const knownEntries = (): Array<SolveEntry & { challengeMeta: ChallengeMeta }> =>
    listSolveEntries(window.localStorage)
      .map((entry) => {
        const challengeMeta = challengeMap.get(`${entry.collection}:${entry.challenge}`);
        return challengeMeta ? { ...entry, challengeMeta } : null;
      })
      .filter((entry): entry is SolveEntry & { challengeMeta: ChallengeMeta } => entry !== null);

  const clearChildren = (node: Element | null) => {
    if (!node) {
      return;
    }

    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  };

  const formatTimestamp = (value?: string): string => {
    if (!value) {
      return "Legacy solve";
    }

    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? "Legacy solve" : dateFormatter.format(parsed);
  };

  const renderCollectionProgress = (entries: Array<SolveEntry & { challengeMeta: ChallengeMeta }>) => {
    if (!(collectionProgressRoot instanceof HTMLElement)) {
      return;
    }

    clearChildren(collectionProgressRoot);

    const solvedSet = new Set(entries.filter((entry) => entry.record.solved).map((entry) => `${entry.collection}:${entry.challenge}`));

    config.collections.forEach((collection) => {
      const total = config.challenges.filter((challenge) => challenge.collection === collection.slug).length;
      const solved = config.challenges.filter((challenge) => solvedSet.has(`${challenge.collection}:${challenge.slug}`)).length;
      const progress = total > 0 ? Math.round((solved / total) * 100) : 0;

      const card = document.createElement("article");
      card.className = "meta-card stats-progress-card";

      const header = document.createElement("div");
      header.className = "stats-progress-head";

      const title = document.createElement("a");
      title.href = collection.path;
      title.className = "stats-progress-link";
      title.textContent = collection.title;

      const meta = document.createElement("span");
      meta.className = "stats-progress-meta";
      meta.textContent = `${solved}/${total}`;

      header.append(title, meta);

      const bar = document.createElement("div");
      bar.className = "stats-progress-bar";

      const fill = document.createElement("span");
      fill.className = "stats-progress-fill";
      fill.style.width = `${progress}%`;
      bar.appendChild(fill);

      const note = document.createElement("p");
      note.className = "muted-copy";
      note.textContent = total > 0 ? `${progress}% complete` : "No challenges published";

      card.append(header, bar, note);
      collectionProgressRoot.appendChild(card);
    });
  };

  const renderRecentSolves = (entries: Array<SolveEntry & { challengeMeta: ChallengeMeta }>) => {
    if (!(recentSolvesRoot instanceof HTMLElement)) {
      return;
    }

    clearChildren(recentSolvesRoot);

    const solvedEntries = entries
      .filter((entry) => entry.record.solved)
      .sort((left, right) => {
        const rightTime = right.record.solvedAt ? Date.parse(right.record.solvedAt) : 0;
        const leftTime = left.record.solvedAt ? Date.parse(left.record.solvedAt) : 0;
        return rightTime - leftTime;
      })
      .slice(0, 10);

    if (solvedEntries.length === 0) {
      const empty = document.createElement("p");
      empty.className = "muted-copy";
      empty.textContent = "No solved challenges are stored on this browser yet.";
      recentSolvesRoot.appendChild(empty);
      return;
    }

    solvedEntries.forEach((entry) => {
      const item = document.createElement("article");
      item.className = "meta-card stats-recent-card";

      const top = document.createElement("div");
      top.className = "stats-recent-head";

      const title = document.createElement("a");
      title.href = entry.challengeMeta.path;
      title.className = "stats-recent-link";
      title.textContent = entry.challengeMeta.title;

      const difficulty = document.createElement("span");
      difficulty.className = `difficulty-pill ${entry.challengeMeta.difficulty}`;
      difficulty.textContent = entry.challengeMeta.difficulty;

      top.append(title, difficulty);

      const meta = document.createElement("div");
      meta.className = "meta-line";

      const collectionName = document.createElement("span");
      collectionName.textContent = collectionMap.get(entry.collection)?.title ?? entry.collection;

      const solvedAt = document.createElement("span");
      solvedAt.textContent = formatTimestamp(entry.record.solvedAt);

      meta.append(collectionName, solvedAt);

      const attempts = document.createElement("p");
      attempts.className = "muted-copy";
      attempts.textContent = `${entry.record.attempts ?? 0} tracked attempt(s)`;

      item.append(top, meta, attempts);
      recentSolvesRoot.appendChild(item);
    });
  };

  const renderMetrics = (entries: Array<SolveEntry & { challengeMeta: ChallengeMeta }>) => {
    const solvedEntries = entries.filter((entry) => entry.record.solved);
    const solvedCount = solvedEntries.length;
    const totalChallenges = config.challenges.length;
    const completionRate = totalChallenges > 0 ? Math.round((solvedCount / totalChallenges) * 100) : 0;
    const collectionCount = new Set(solvedEntries.map((entry) => entry.collection)).size;
    const attemptCount = entries.reduce((sum, entry) => sum + (entry.record.attempts ?? 0), 0);

    if (metricNodes.solvedCount instanceof HTMLElement) {
      metricNodes.solvedCount.textContent = String(solvedCount);
    }

    if (metricNodes.completionRate instanceof HTMLElement) {
      metricNodes.completionRate.textContent = `${completionRate}%`;
    }

    if (metricNodes.collectionCount instanceof HTMLElement) {
      metricNodes.collectionCount.textContent = String(collectionCount);
    }

    if (metricNodes.attemptCount instanceof HTMLElement) {
      metricNodes.attemptCount.textContent = String(attemptCount);
    }
  };

  const renderAll = () => {
    const entries = knownEntries();
    renderMetrics(entries);
    renderCollectionProgress(entries);
    renderRecentSolves(entries);
  };

  const downloadFile = (filename: string, content: string, type: string) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  if (exportButton instanceof HTMLButtonElement) {
    exportButton.addEventListener("click", () => {
      const payload: ExportPayload = {
        version: 1,
        exportedAt: new Date().toISOString(),
        entries: knownEntries().map((entry) => ({
          collection: entry.collection,
          challenge: entry.challenge,
          record: entry.record
        }))
      };

      downloadFile("xe_stats_progress.json", JSON.stringify(payload, null, 2), "application/json");
      setStatus("Progress exported to xe_stats_progress.json");
    });
  }

  if (importButton instanceof HTMLButtonElement && importInput instanceof HTMLInputElement) {
    importButton.addEventListener("click", () => {
      importInput.click();
    });

    importInput.addEventListener("change", async () => {
      const file = importInput.files?.[0];

      if (!file) {
        return;
      }

      try {
        const raw = await file.text();
        const parsed = JSON.parse(raw) as Partial<ExportPayload>;
        const importedEntries = Array.isArray(parsed.entries) ? parsed.entries : [];
        let importedCount = 0;

        importedEntries.forEach((entry) => {
          if (!entry || typeof entry !== "object") {
            return;
          }

          const collection = typeof entry.collection === "string" ? entry.collection : "";
          const challenge = typeof entry.challenge === "string" ? entry.challenge : "";
          const record = entry.record;

          if (!collection || !challenge || typeof record !== "object" || record === null) {
            return;
          }

          const storageKey = createSolveStorageKey(collection, challenge);
          writeSolveRecord(
            storageKey,
            {
              solved: Boolean(record.solved),
              solvedAt: typeof record.solvedAt === "string" ? record.solvedAt : undefined,
              attempts: typeof record.attempts === "number" ? record.attempts : undefined,
              lastTriedAt: typeof record.lastTriedAt === "string" ? record.lastTriedAt : undefined
            },
            window.localStorage
          );
          importedCount += 1;
        });

        renderAll();
        setStatus(`Imported ${importedCount} progress record(s).`);
      } catch {
        setStatus("Import failed. Use a JSON export generated from this stats page.");
      } finally {
        importInput.value = "";
      }
    });
  }

  if (resetButton instanceof HTMLButtonElement) {
    resetButton.addEventListener("click", () => {
      const entries = listSolveEntries(window.localStorage);

      if (entries.length === 0) {
        setStatus("No local progress records found to reset.");
        return;
      }

      const confirmed = window.confirm("Delete all local solve progress from this browser?");

      if (!confirmed) {
        return;
      }

      entries.forEach((entry) => {
        window.localStorage.removeItem(entry.storageKey);
      });

      renderAll();
      setStatus("All local solve progress was cleared from this browser.");
    });
  }

  window.addEventListener("storage", renderAll);
  renderAll();
}
