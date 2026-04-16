export interface SolveRecord {
  solved: boolean;
  solvedAt?: string;
  attempts?: number;
  lastTriedAt?: string;
}

export interface SolveEntry {
  storageKey: string;
  collection: string;
  challenge: string;
  record: SolveRecord;
}

export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  key(index: number): string | null;
  length: number;
}

export const SOLVE_KEY_PREFIX = "ctf:solved:";

export function createSolveStorageKey(collection: string, challenge: string): string {
  return `${SOLVE_KEY_PREFIX}${collection}:${challenge}`;
}

export function parseSolveRecord(raw: string | null): SolveRecord | null {
  if (!raw) {
    return null;
  }

  if (raw === "true") {
    return { solved: true };
  }

  try {
    const parsed = JSON.parse(raw) as Partial<SolveRecord>;

    if (typeof parsed !== "object" || parsed === null) {
      return null;
    }

    return {
      solved: Boolean(parsed.solved),
      solvedAt: typeof parsed.solvedAt === "string" ? parsed.solvedAt : undefined,
      attempts: typeof parsed.attempts === "number" && Number.isFinite(parsed.attempts) ? parsed.attempts : undefined,
      lastTriedAt: typeof parsed.lastTriedAt === "string" ? parsed.lastTriedAt : undefined
    };
  } catch {
    return null;
  }
}

export function readSolveRecord(storageKey: string, storage?: StorageLike): SolveRecord | null {
  if (!storageKey || !storage) {
    return null;
  }

  return parseSolveRecord(storage.getItem(storageKey));
}

export function writeSolveRecord(storageKey: string, record: SolveRecord, storage?: StorageLike): void {
  if (!storageKey || !storage) {
    return;
  }

  storage.setItem(storageKey, JSON.stringify(record));
}

export function listSolveEntries(storage?: StorageLike): SolveEntry[] {
  if (!storage) {
    return [];
  }

  const entries: SolveEntry[] = [];

  for (let index = 0; index < storage.length; index += 1) {
    const key = storage.key(index);

    if (!key || !key.startsWith(SOLVE_KEY_PREFIX)) {
      continue;
    }

    const record = parseSolveRecord(storage.getItem(key));

    if (!record) {
      continue;
    }

    const segments = key.slice(SOLVE_KEY_PREFIX.length).split(":");
    const collection = segments.shift() ?? "";
    const challenge = segments.join(":");

    if (!collection || !challenge) {
      continue;
    }

    entries.push({
      storageKey: key,
      collection,
      challenge,
      record
    });
  }

  return entries;
}
