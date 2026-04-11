export function withBase(path: string): string {
  if (!path || /^https?:\/\//.test(path) || path.startsWith("#") || path.startsWith("mailto:")) {
    return path;
  }

  const base = (import.meta.env.BASE_URL || "/").replace(/\/$/, "");
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;

  return `${base}${normalizedPath}` || normalizedPath;
}
