export function normalizeAnswer(value: string): string {
  return value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .trim()
    .replace(/[`'"’"]/g, "")
    .replace(/[_\s]+/g, " ")
    .replace(/\s+/g, " ");
}

export async function hashAnswerHex(value: string): Promise<string> {
  const cryptoObject = globalThis.crypto;

  if (!cryptoObject?.subtle) {
    throw new Error("Web Crypto API is not available in this environment.");
  }

  const bytes = new TextEncoder().encode(value);
  const digest = await cryptoObject.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function normalizeAndHashAnswer(value: string): Promise<string> {
  return hashAnswerHex(normalizeAnswer(value));
}
