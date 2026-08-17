import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { writeFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { carvePEFromData } from "./pe_carver.mjs";

/**
 * Enterprise Multi-Stage Recursive Deobfuscator & Deep PE Extractor (v2.4)
 */

export function extractXORKeysFromScript(scriptText) {
  const keys = [];

  // Pattern 1: $k = [byte[]](0xAA, 0xBB, ...)
  const byteKeyMatch = scriptText.match(/\$k\s*=\s*\[byte\[\]\]\(([^)]+)\)/i);
  if (byteKeyMatch) {
    const rawBytes = byteKeyMatch[1]
      .split(",")
      .map((s) => parseInt(s.trim(), 16))
      .filter((n) => !isNaN(n));
    if (rawBytes.length > 0) {
      keys.push({
        type: "byte_array",
        source: "PowerShell Byte Array ($k)",
        bytes: Buffer.from(rawBytes),
        hex: Buffer.from(rawBytes).toString("hex"),
        ascii: Buffer.from(rawBytes).toString("ascii").replace(/[^\x20-\x7E]/g, ".")
      });
    }
  }

  // Pattern 2: Multiline Hex Key ($decryptionHexKey / $hexKey / $key)
  const hexKeyMatch = scriptText.match(/\$(?:decryptionHexKey|hexKey|encryptionKey|keyHex|xorKey)\s*=\s*(?:@'|@"|'|")([\s\S]*?)(?:'@|"@|'|")/i);
  if (hexKeyMatch) {
    const cleanHex = hexKeyMatch[1].replace(/[^0-9a-fA-F]/g, "");
    if (cleanHex.length >= 8 && cleanHex.length % 2 === 0) {
      const keyBuffer = Buffer.from(cleanHex, "hex");
      keys.push({
        type: "hex_string",
        source: "PowerShell Hex Key ($decryptionHexKey)",
        bytes: keyBuffer,
        hex: cleanHex,
        ascii: keyBuffer.toString("ascii").replace(/[^\x20-\x7E]/g, ".")
      });
    }
  }

  // Pattern 3: String Crypto Keys ($cryptoKey = "...")
  const strKeyMatches = [...scriptText.matchAll(/\$(?:cryptoKey|key|password|secret|keyString)\s*=\s*["']([^"']{4,64})["']/gi)];
  for (const m of strKeyMatches) {
    const strBuf = Buffer.from(m[1], "utf-8");
    keys.push({
      type: "ascii_string",
      source: `Script Key ($${m[0].split("=")[0].replace("$", "").trim()})`,
      bytes: strBuf,
      hex: strBuf.toString("hex"),
      ascii: m[1]
    });
  }

  return keys;
}

export function decryptXOR(dataBuffer, keyBuffer) {
  if (!dataBuffer || !keyBuffer || keyBuffer.length === 0) return null;
  const result = Buffer.alloc(dataBuffer.length);
  for (let i = 0; i < dataBuffer.length; i++) {
    result[i] = dataBuffer[i] ^ keyBuffer[i % keyBuffer.length];
  }
  return result;
}

export function parseScriptBehavior(scriptText) {
  const behavior = {
    scheduledTasks: [],
    pInvokeMethods: [],
    comObjects: [],
    networkEndpoints: [],
    reflectionLoading: false
  };

  const taskMatches = [...scriptText.matchAll(/schtasks[^\r\n"']+/gi)].map((m) => m[0]);
  behavior.scheduledTasks.push(...taskMatches);

  const pinvokeMatches = [...scriptText.matchAll(/(\[DllImport\([^)]+\)\][\s\S]*?public\s+static\s+extern[^\r\n;]+;)/gi)].map((m) => m[0]);
  behavior.pInvokeMethods.push(...pinvokeMatches);

  if (/VirtualAlloc|Marshal\.Copy|CreateThread/i.test(scriptText)) {
    behavior.pInvokeMethods.push("In-Memory Shellcode Execution (VirtualAlloc / Marshal.Copy)");
  }

  if (/\[System\.Reflection\.Assembly\]::Load/i.test(scriptText)) {
    behavior.reflectionLoading = true;
  }

  const comMatches = [...scriptText.matchAll(/New-Object\s+-ComObject\s+['"]?([^'"\s]+)['"]?/gi)].map((m) => m[1]);
  behavior.comObjects.push(...comMatches);

  const urls = [...scriptText.matchAll(/https?:\/\/[^\s"'<>]+/gi)].map((m) => m[0]);
  behavior.networkEndpoints.push(...urls);

  return behavior;
}

export async function analyzeAndDeobfuscateFiles(files, outputDir = "./threat_intel_acquisitions/carved") {
  await mkdir(outputDir, { recursive: true });

  const deobfResults = {
    recoveredKeys: [],
    decryptedArtifacts: [],
    carvedBinaries: [],
    scriptBehaviors: [],
    decodedBase64: []
  };

  // Pass 1: Extract Keys and Initial Behaviors
  for (const file of files) {
    const keys = extractXORKeysFromScript(file.content);
    if (keys.length > 0) deobfResults.recoveredKeys.push(...keys);

    const behavior = parseScriptBehavior(file.content);
    if (behavior.scheduledTasks.length > 0 || behavior.pInvokeMethods.length > 0 || behavior.comObjects.length > 0 || behavior.reflectionLoading) {
      deobfResults.scriptBehaviors.push({ filename: file.filename, ...behavior });
    }

    const directPEs = await carvePEFromData(file.content, file.filename, outputDir);
    if (directPEs.length > 0) deobfResults.carvedBinaries.push(...directPEs);
  }

  // Pass 2: Hex Layer Decryption (Layer 1)
  for (const file of files) {
    const cipherMatch = file.content.match(/\$(?:encryptedHexData|cipherHexData|hexData|encData|payloadHex)\s*=\s*(?:@'|@"|'|")([\s\S]*?)(?:'@|"@|'|")/i);
    if (cipherMatch) {
      const cleanCipherHex = cipherMatch[1].replace(/[^0-9a-fA-F]/g, "");
      if (cleanCipherHex.length >= 32) {
        const cipherBuf = Buffer.from(cleanCipherHex, "hex");

        for (const key of deobfResults.recoveredKeys) {
          const decrypted = decryptXOR(cipherBuf, key.bytes);
          if (decrypted && decrypted.length > 0) {
            const utf8Str = decrypted.toString("utf-8");
            const isPE = decrypted.slice(0, 2).toString("ascii") === "MZ";

            deobfResults.decryptedArtifacts.push({
              sourceFile: `${file.filename} -> Layer 1 Decrypted`,
              layer: 1,
              keyUsed: key.ascii,
              keyHex: key.hex,
              decryptedLength: decrypted.length,
              isPEHeader: isPE,
              hexHeader: decrypted.slice(0, 16).toString("hex"),
              previewString: utf8Str.slice(0, 300)
            });

            // Carve direct PEs from Layer 1
            const carvedL1 = await carvePEFromData(decrypted, `${file.filename} (Layer 1)`, outputDir);
            if (carvedL1.length > 0) deobfResults.carvedBinaries.push(...carvedL1);

            // Layer 2: Extract Nested XOR Keys & Decrypt Second-Stage .NET Assembly / EXE
            const l2Keys = extractXORKeysFromScript(utf8Str);
            for (const l2k of l2Keys) {
              if (!deobfResults.recoveredKeys.some((k) => k.ascii === l2k.ascii)) {
                deobfResults.recoveredKeys.push(l2k);
              }
            }

            // Pattern A: $encodedPayload = '...' with Base64 XOR in Layer 2
            const encPayloadMatch = utf8Str.match(/\$(?:encodedPayload|nestedPayload|stage2Payload)\s*=\s*["']([A-Za-z0-9+/=]{100,})["']/i);
            if (encPayloadMatch) {
              const encB64 = encPayloadMatch[1];
              const encBuf = Buffer.from(encB64, "base64");

              for (const l2k of deobfResults.recoveredKeys) {
                const decL2 = decryptXOR(encBuf, l2k.bytes);
                if (decL2) {
                  try {
                    const decB64Str = decL2.toString("utf-8");
                    const dllBytes = Buffer.from(decB64Str, "base64");
                    if (dllBytes.slice(0, 2).toString("ascii") === "MZ") {
                      const sha256 = createHash("sha256").update(dllBytes).digest("hex");
                      const filename = `carved_layer2_loader_${sha256.slice(0, 8)}.dll`;
                      const filePath = resolve(outputDir, filename);
                      await writeFile(filePath, dllBytes);

                      deobfResults.carvedBinaries.push({
                        filename,
                        type: "Carved Layer 2 .NET Reflection Loader (DLL)",
                        sha256,
                        sizeBytes: dllBytes.length,
                        source: `${file.filename} (Layer 2 XOR -> Base64)`,
                        path: filePath
                      });
                    }
                  } catch (e) {}
                }
              }
            }

            // Pattern B: [Byte[]]$payloadBytes = (77,90,69,82,...) in Layer 2
            const payloadBytesIdx = utf8Str.indexOf("$payloadBytes = (");
            if (payloadBytesIdx !== -1) {
              const sub = utf8Str.slice(payloadBytesIdx + "$payloadBytes = (".length);
              const endIdx = sub.indexOf(")");
              const numStr = sub.slice(0, endIdx);
              const nums = numStr.split(",").map((n) => parseInt(n.trim(), 10)).filter((n) => !isNaN(n));
              if (nums.length > 512) {
                const exeBuf = Buffer.from(nums);
                if (exeBuf.slice(0, 2).toString("ascii") === "MZ" || exeBuf.slice(0, 4).toString("ascii") === "MZER") {
                  const sha256 = createHash("sha256").update(exeBuf).digest("hex");
                  const filename = `carved_layer2_payload_${sha256.slice(0, 8)}.exe`;
                  const filePath = resolve(outputDir, filename);
                  await writeFile(filePath, exeBuf);

                  deobfResults.carvedBinaries.push({
                    filename,
                    type: "Carved Layer 2 Executable Payload (EXE/Shellcode)",
                    sha256,
                    sizeBytes: exeBuf.length,
                    source: `${file.filename} (Layer 2 Byte Array)`,
                    path: filePath
                  });
                }
              }
            }
          }
        }
      }
    }
  }

  return deobfResults;
}
