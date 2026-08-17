/**
 * High-Precision Defang Engine for Threat Intelligence
 */
export function defang(text) {
  if (!text) return "";
  let res = String(text)
    .replace(/http:\/\//gi, "hxxp://")
    .replace(/https:\/\//gi, "hxxps://")
    .replace(/ftp:\/\//gi, "fxp://");

  // Defang IPv4 addresses (excluding localhost and markdown image paths)
  res = res.replace(/\b(?<![\/|\w])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b(?!\.png|\.jpg|\.webp)/g, (match, p1, p2, p3, p4) => {
    if (match.startsWith("127.") || match.startsWith("0.0.")) return match;
    return `${p1}[.]${p2}[.]${p3}[.]${p4}`;
  });

  // Defang external URLs/domains
  res = res.replace(/(hxxps?:\/\/[a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})/g, (match) => {
    if (match.includes("xelessaway.me") || match.includes("github.com") || match.includes("google.com")) return match;
    return match.replace(/\.([a-zA-Z]{2,})$/, "[.]$1");
  });

  return res;
}
