import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { writeFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";

/**
 * Enterprise In-Memory PE / DLL Carving Engine
 * Detects and extracts embedded Windows Executables (.exe), Dynamic Link Libraries (.dll),
 * and Kernel Drivers (.sys) from byte arrays, hex streams, and Base64 payloads.
 */

export async function carvePEFromData(data, sourceName, outputDir = "./threat_intel_acquisitions/carved") {
  const carvedBinaries = [];
  await mkdir(outputDir, { recursive: true });

  let text = "";
  let buffer = null;

  if (Buffer.isBuffer(data)) {
    buffer = data;
    text = data.toString("utf-8");
  } else if (typeof data === "string") {
    text = data;
    buffer = Buffer.from(data, "binary");
  }

  // Method 1: Raw MZ Magic Byte Carving inside binary buffer
  if (buffer && buffer.length > 512) {
    for (let i = 0; i < buffer.length - 256; i++) {
      if (buffer[i] === 0x4d && buffer[i + 1] === 0x5a) { // "MZ"
        const e_lfanew = buffer.readUInt32LE(i + 0x3c);
        if (e_lfanew > 0 && e_lfanew < 1024 && i + e_lfanew + 4 <= buffer.length) {
          const peSig = buffer.slice(i + e_lfanew, i + e_lfanew + 4).toString("ascii");
          if (peSig === "PE\0\0") {
            // Identified valid PE Header
            const peBuffer = buffer.slice(i);
            const sha256 = createHash("sha256").update(peBuffer).digest("hex");
            const isDll = (peBuffer.readUInt16LE(i + e_lfanew + 22) & 0x2000) !== 0;
            const ext = isDll ? "dll" : "exe";
            const filename = `carved_${sha256.slice(0, 8)}.${ext}`;
            const filePath = resolve(outputDir, filename);

            await writeFile(filePath, peBuffer);

            carvedBinaries.push({
              filename,
              type: isDll ? "Carved Dynamic Link Library (DLL)" : "Carved Windows Executable (EXE)",
              sha256,
              sizeBytes: peBuffer.length,
              source: sourceName,
              path: filePath
            });
            break; // Carved primary PE
          }
        }
      }
    }
  }

  // Method 2: Base64 Encoded PE Carving (TVqQ / TVoA / TVpQ)
  const b64PeMatches = [...text.matchAll(/\b(TVqQ[A-Za-z0-9+/=]{100,}|TVoA[A-Za-z0-9+/=]{100,}|TVpQ[A-Za-z0-9+/=]{100,})\b/g)];
  for (const match of b64PeMatches) {
    try {
      const decoded = Buffer.from(match[1], "base64");
      if (decoded.slice(0, 2).toString("ascii") === "MZ") {
        const sha256 = createHash("sha256").update(decoded).digest("hex");
        const filename = `carved_b64_${sha256.slice(0, 8)}.exe`;
        const filePath = resolve(outputDir, filename);

        await writeFile(filePath, decoded);

        carvedBinaries.push({
          filename,
          type: "Base64 Decoded PE Binary (EXE/DLL)",
          sha256,
          sizeBytes: decoded.length,
          source: sourceName,
          path: filePath
        });
      }
    } catch (e) {}
  }

  // Method 3: Hex Encoded PE Carving (4D5A...)
  const hexPeMatches = [...text.matchAll(/(?:'|")?(4D5A9000[0-9A-Fa-f]{100,})(?:'|")?/gi)];
  for (const match of hexPeMatches) {
    try {
      const cleanHex = match[1].replace(/[^0-9a-fA-F]/g, "");
      const decoded = Buffer.from(cleanHex, "hex");
      if (decoded.slice(0, 2).toString("ascii") === "MZ") {
        const sha256 = createHash("sha256").update(decoded).digest("hex");
        const filename = `carved_hex_${sha256.slice(0, 8)}.exe`;
        const filePath = resolve(outputDir, filename);

        await writeFile(filePath, decoded);

        carvedBinaries.push({
          filename,
          type: "Hex Decoded PE Binary (EXE/DLL)",
          sha256,
          sizeBytes: decoded.length,
          source: sourceName,
          path: filePath
        });
      }
    } catch (e) {}
  }

  // Method 4: PowerShell Byte Array Carving (@(0x4D, 0x5A, ...) or 0x4D,0x5A,...)
  const byteArrMatch = text.match(/(?:0x4D\s*,\s*0x5A\s*,\s*0x90[\s\S]{100,})/i);
  if (byteArrMatch) {
    try {
      const bytes = [...byteArrMatch[0].matchAll(/0x([0-9a-fA-F]{1,2})/g)].map((m) => parseInt(m[1], 16));
      if (bytes.length > 512) {
        const decoded = Buffer.from(bytes);
        if (decoded.slice(0, 2).toString("ascii") === "MZ") {
          const sha256 = createHash("sha256").update(decoded).digest("hex");
          const filename = `carved_bytes_${sha256.slice(0, 8)}.exe`;
          const filePath = resolve(outputDir, filename);

          await writeFile(filePath, decoded);

          carvedBinaries.push({
            filename,
            type: "Byte Array Decoded PE (EXE/DLL)",
            sha256,
            sizeBytes: decoded.length,
            source: sourceName,
            path: filePath
          });
        }
      }
    } catch (e) {}
  }

  return carvedBinaries;
}
