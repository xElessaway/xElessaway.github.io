import { Buffer } from "node:buffer";
import { carvePEFromData } from "./pe_carver.mjs";

/**
 * Enterprise Recursive Multi-Layer Deobfuscation Engine (v2.3)
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

  // Pattern 2: Multiline or Single-line Hex Key ($decryptionHexKey / $hexKey / $key)
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

  // Pattern 3: Key derivation strings
  const strKeyMatch = scriptText.match(/\$(?:key|password|secret)\s*=\s*['"]([^'"]{4,64})['"]/i);
  if (strKeyMatch) {
    const strBuf = Buffer.from(strKeyMatch[1], "utf-8");
    keys.push({
      type: "ascii_string",
      source: `Script Variable ($${strKeyMatch[0].split("=")[0].replace("$", "").trim()})`,
      bytes: strBuf,
      hex: strBuf.toString("hex"),
      ascii: strKeyMatch[1]
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

export async function analyzeAndDeobfuscateFiles(files) {
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

    // Attempt direct PE Carving from the raw source
    const directPEs = await carvePEFromData(file.content, file.filename);
    if (directPEs.length > 0) deobfResults.carvedBinaries.push(...directPEs);
  }

  // Recursive Multi-Pass Decryption & Carving (Up to 4 Layers)
  let pendingBuffers = [];

  // Seed pending buffers from files
  for (const file of files) {
    // 1. Inline Hex in scripts
    const inlineHexMatch = file.content.match(/\$(?:encryptedHexData|cipherHexData|hexData|encData|payloadHex)\s*=\s*(?:@'|@"|'|")([\s\S]*?)(?:'@|"@|'|")/i);
    if (inlineHexMatch) {
      const cleanCipherHex = inlineHexMatch[1].replace(/[^0-9a-fA-F]/g, "");
      if (cleanCipherHex.length >= 32) {
        pendingBuffers.push({
          source: `${file.filename} (Inline Hex Layer 1)`,
          buffer: Buffer.from(cleanCipherHex, "hex"),
          layer: 1
        });
      }
    }

    // 2. Binary files
    if (file.filename.endsWith(".dat") || file.filename.endsWith(".bin")) {
      pendingBuffers.push({
        source: `${file.filename} (Binary Layer 1)`,
        buffer: Buffer.from(file.content, "binary"),
        layer: 1
      });
    }
  }

  let layerCount = 1;
  while (pendingBuffers.length > 0 && layerCount <= 4) {
    const nextLayerBuffers = [];

    for (const item of pendingBuffers) {
      for (const key of deobfResults.recoveredKeys) {
        const decrypted = decryptXOR(item.buffer, key.bytes);
        if (decrypted && decrypted.length > 0) {
          const isPE = decrypted.slice(0, 2).toString("ascii") === "MZ";
          const hexHead = decrypted.slice(0, 16).toString("hex");
          const utf8Str = decrypted.toString("utf-8");

          deobfResults.decryptedArtifacts.push({
            sourceFile: `${item.source} -> Layer ${layerCount} Decrypted`,
            layer: layerCount,
            keyUsed: key.ascii,
            keyHex: key.hex,
            decryptedLength: decrypted.length,
            isPEHeader: isPE,
            hexHeader: hexHead,
            previewString: utf8Str.slice(0, 300)
          });

          // Carve embedded PEs from decrypted payload
          const carved = await carvePEFromData(decrypted, `${item.source} (Layer ${layerCount})`);
          if (carved.length > 0) {
            deobfResults.carvedBinaries.push(...carved);
          }

          // Check if the decrypted code contains nested secondary keys or hex payloads
          const secondaryKeys = extractXORKeysFromScript(utf8Str);
          if (secondaryKeys.length > 0) {
            for (const sk of secondaryKeys) {
              if (!deobfResults.recoveredKeys.some((k) => k.hex === sk.hex)) {
                deobfResults.recoveredKeys.push(sk);
              }
            }
          }

          const secondaryHexMatch = utf8Str.match(/\$(?:encryptedHexData|cipherHexData|hexData|encData|payloadHex)\s*=\s*(?:@'|@"|'|")([\s\S]*?)(?:'@|"@|'|")/i);
          if (secondaryHexMatch) {
            const cleanSecHex = secondaryHexMatch[1].replace(/[^0-9a-fA-F]/g, "");
            if (cleanSecHex.length >= 32) {
              nextLayerBuffers.push({
                source: `${item.source} -> Nested Payload`,
                buffer: Buffer.from(cleanSecHex, "hex"),
                layer: layerCount + 1
              });
            }
          }
        }
      }
    }

    pendingBuffers = nextLayerBuffers;
    layerCount++;
  }

  return deobfResults;
}
