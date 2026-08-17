import fs from "fs";
import { createHash } from "crypto";

const code = fs.readFileSync("F:/Full Agent/threat_intel_acquisitions/178_16_53_176_80/crypted.ps1_dec.txt", "utf8");

// 1. Extract and Decrypt .NET DLL
const keyMatch = code.match(/\$cryptoKey\s*=\s*["']([^"']+)["']/);
const cryptoKey = keyMatch ? keyMatch[1] : "";
console.log("🔑 Layer 2 Crypto Key:", cryptoKey);

const encMatch = code.match(/\$encodedPayload\s*=\s*["']([^"']+)["']/);
if (encMatch && cryptoKey) {
  const encB64 = encMatch[1];
  const encBuf = Buffer.from(encB64, "base64");
  const keyBuf = Buffer.from(cryptoKey, "utf8");

  const decDllB64Buf = Buffer.alloc(encBuf.length);
  for (let i = 0; i < encBuf.length; i++) {
    decDllB64Buf[i] = encBuf[i] ^ keyBuf[i % keyBuf.length];
  }
  const decDllB64Str = decDllB64Buf.toString("utf8");
  const dllBytes = Buffer.from(decDllB64Str, "base64");
  const dllSha256 = createHash("sha256").update(dllBytes).digest("hex");

  console.log(`\n📦 Carved DLL: extracted_loader.dll`);
  console.log(`   Header: ${dllBytes.slice(0, 2).toString("ascii")} (${dllBytes.slice(0, 16).toString("hex")})`);
  console.log(`   Size: ${dllBytes.length} bytes`);
  console.log(`   SHA256: ${dllSha256}`);

  fs.writeFileSync("F:/Full Agent/threat_intel_acquisitions/178_16_53_176_80/extracted_loader.dll", dllBytes);
}

// 2. Extract [Byte[]]$payloadBytes EXE
const payloadIdx = code.indexOf("$payloadBytes = (");
if (payloadIdx !== -1) {
  const payloadSub = code.slice(payloadIdx + "$payloadBytes = (".length);
  const endIdx = payloadSub.indexOf(")");
  const numStr = payloadSub.slice(0, endIdx);
  const nums = numStr.split(",").map((n) => parseInt(n.trim(), 10)).filter((n) => !isNaN(n));
  const exeBuf = Buffer.from(nums);
  const exeSha256 = createHash("sha256").update(exeBuf).digest("hex");

  console.log(`\n📦 Carved Executable: extracted_payload.exe`);
  console.log(`   Header: ${exeBuf.slice(0, 4).toString("ascii")} (${exeBuf.slice(0, 16).toString("hex")})`);
  console.log(`   Size: ${exeBuf.length} bytes`);
  console.log(`   SHA256: ${exeSha256}`);

  fs.writeFileSync("F:/Full Agent/threat_intel_acquisitions/178_16_53_176_80/extracted_payload.exe", exeBuf);
}
