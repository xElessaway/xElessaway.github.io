import { defang } from "./defang.mjs";

/**
 * High-Precision Secret, Credential, and API Harvester
 */

export function harvestSecrets(files) {
  const harvested = [];

  for (const file of files) {
    const text = file.content;
    const filename = file.filename;

    // 1. GitHub Tokens
    const ghTokens = [...text.matchAll(/\b(ghp_[A-Za-z0-9_]{36,40}|gho_[A-Za-z0-9_]{36,40}|github_pat_[A-Za-z0-9_]{82})\b/g)].map((m) => m[1]);
    ghTokens.forEach((tok) => {
      harvested.push({
        type: "GitHub Personal Access Token",
        value: `${tok.slice(0, 8)}...${tok.slice(-4)} (Redacted for OpSec)`,
        rawPreview: tok.slice(0, 10) + "...",
        sourceFile: filename,
        category: "API & Cloud Credentials",
        risk: "Critical"
      });
    });

    // 2. Google OAuth Tokens & Client Secrets
    const googleClientId = [...text.matchAll(/\b([0-9]+-[a-z0-9_]+\.apps\.googleusercontent\.com)\b/gi)].map((m) => m[1]);
    googleClientId.forEach((cid) => {
      harvested.push({
        type: "Google OAuth Client ID",
        value: cid,
        rawPreview: cid,
        sourceFile: filename,
        category: "Cloud Infrastructure",
        risk: "High"
      });
    });

    const googleClientSecret = [...text.matchAll(/\b(GOCSPX-[A-Za-z0-9_-]{28})\b/g)].map((m) => m[1]);
    googleClientSecret.forEach((sec) => {
      harvested.push({
        type: "Google OAuth Client Secret",
        value: `${sec.slice(0, 10)}... (Redacted)`,
        rawPreview: sec.slice(0, 12) + "...",
        sourceFile: filename,
        category: "API & Cloud Credentials",
        risk: "Critical"
      });
    });

    // 3. Google Service Account / Refresh Tokens
    if (text.includes("private_key_id") && text.includes("client_email")) {
      const emailMatch = text.match(/"client_email":\s*"([^"]+)"/);
      harvested.push({
        type: "Google Cloud Service Account JSON",
        value: emailMatch ? `Client Email: ${emailMatch[1]}` : "GCP Service Account Detected",
        rawPreview: "Google Cloud Service Account",
        sourceFile: filename,
        category: "Cloud Infrastructure",
        risk: "Critical"
      });
    }

    // 4. SSH Credentials & sshpass
    const sshPassMatch = [...text.matchAll(/sshpass\s+-p\s+['"]?([^'"\s]+)['"]?\s+ssh\s+([^\s\r\n]+)/gi)];
    sshPassMatch.forEach((m) => {
      harvested.push({
        type: "SSH Password & Connection Target",
        value: `Target: ${defang(m[2])} | Password: ${m[1]}`,
        rawPreview: `sshpass -p '${m[1]}' ssh ${m[2]}`,
        sourceFile: filename,
        category: "Lateral Movement & SSH Access",
        risk: "Critical"
      });
    });

    // 5. Private Keys (RSA, OpenSSH, EC)
    if (/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/i.test(text)) {
      harvested.push({
        type: "Private Cryptographic Key",
        value: "Embedded RSA/OpenSSH Private Key Block",
        rawPreview: "-----BEGIN PRIVATE KEY-----",
        sourceFile: filename,
        category: "Cryptographic Keys",
        risk: "Critical"
      });
    }

    // 6. Telegram Bot Tokens
    const tgMatch = [...text.matchAll(/\b([0-9]{8,10}:[A-Za-z0-9_-]{35})\b/g)].map((m) => m[1]);
    tgMatch.forEach((tg) => {
      harvested.push({
        type: "Telegram Bot Token",
        value: `${tg.slice(0, 12)}... (Redacted)`,
        rawPreview: tg.slice(0, 12) + "...",
        sourceFile: filename,
        category: "C2 Exfiltration Channel",
        risk: "High"
      });
    });

    // 7. Discord Webhooks
    const discordMatch = [...text.matchAll(/https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/gi)].map((m) => m[0]);
    discordMatch.forEach((dw) => {
      harvested.push({
        type: "Discord Exfiltration Webhook",
        value: `${dw.slice(0, 45)}...`,
        rawPreview: dw,
        sourceFile: filename,
        category: "C2 Exfiltration Channel",
        risk: "High"
      });
    });

    // 8. Database Credentials (MySQL, PostgreSQL, MongoDB, Redis)
    const dbMatch = [...text.matchAll(/(?:mysql|postgres|mongodb|redis):\/\/(?:([^:]+):([^@]+)@)?([^\/:\s]+)(?::([0-9]+))?/gi)];
    dbMatch.forEach((db) => {
      harvested.push({
        type: "Database Connection String",
        value: `Host: ${defang(db[3])} | User: ${db[1] || "root"} | Pass: ${db[2] || "none"}`,
        rawPreview: db[0],
        sourceFile: filename,
        category: "Database Telemetry",
        risk: "High"
      });
    });

    // 9. AWS Access Keys
    const awsMatch = [...text.matchAll(/\b(AKIA[0-9A-Z]{16})\b/g)].map((m) => m[1]);
    awsMatch.forEach((ak) => {
      harvested.push({
        type: "AWS Access Key ID",
        value: ak,
        rawPreview: ak,
        sourceFile: filename,
        category: "Cloud Infrastructure",
        risk: "High"
      });
    });

    // 10. Generic Hardcoded Credentials in Scripts
    const pwdMatches = [...text.matchAll(/(?:password|passwd|secret_key|api_secret|auth_token)\s*[:=]\s*['"]([^'"]{6,60})['"]/gi)];
    pwdMatches.forEach((pm) => {
      if (!harvested.some((h) => h.sourceFile === filename && h.rawPreview === pm[1])) {
        harvested.push({
          type: "Hardcoded Credential / Secret",
          value: pm[1],
          rawPreview: `${pm[0].slice(0, 30)}...`,
          sourceFile: filename,
          category: "Discovered Credentials",
          risk: "Medium"
        });
      }
    });
  }

  return harvested;
}
