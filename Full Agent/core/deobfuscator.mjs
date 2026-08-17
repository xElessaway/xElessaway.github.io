import { Buffer } from "node:buffer";

/**
 * Automated Deobfuscator Engine
 * Handles: Multi-byte & Single-byte XOR, Base64, PowerShell, MSHTA, JScript, and VBScript
 */

// 1. Detect and Decrypt XOR Payloads
export function decryptXOR(payloadBuffer, keyBytes) {
  if (!payloadBuffer || !keyBytes || keyBytes.length === 0) return null;
  const result = Buffer.alloc(payloadBuffer.length);
  for (let i = 0; i < payloadBuffer.length; i++) {
    result[i] = payloadBuffer[i] ^ keyBytes[i % keyBytes.length];
  }
  return result;
}

// 2. Scan Text for Hardcoded XOR Keys (PowerShell, C, Python)
export function extractXORKeysFromScript(scriptText) {
  const keys = [];

  // PowerShell byte array syntax: $k = [byte[]]@(75,55,109,81,50,112,76,57)
  const psKeyMatch = scriptText.match(/\$k\s*=\s*\[byte\[\]\]@\(([0-9,\s]+)\)/i);
  if (psKeyMatch) {
    const bytes = psKeyMatch[1].split(",").map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n));
    if (bytes.length > 0) {
      keys.push({
        source: "PowerShell Array ($k)",
        bytes: bytes,
        ascii: String.fromCharCode(...bytes),
        hex: Buffer.from(bytes).toString("hex")
      });
    }
  }

  // PowerShell multiline hex key syntax: $decryptionHexKey = @'...'@ or "..."
  const psHexKeyMatch = scriptText.match(/\$(?:decryptionHexKey|hexKey|keyHex|xorKeyHex)\s*=\s*(?:@'|@"|'|")([\s\S]*?)(?:'@|"@|'|")/i);
  if (psHexKeyMatch) {
    const cleanHex = psHexKeyMatch[1].replace(/[^0-9a-fA-F]/g, "");
    if (cleanHex.length >= 8 && cleanHex.length % 2 === 0) {
      const bytes = Array.from(Buffer.from(cleanHex, "hex"));
      keys.push({
        source: "PowerShell Hex Key ($decryptionHexKey)",
        bytes: bytes,
        ascii: Buffer.from(bytes).toString("utf-8").replace(/[^\x20-\x7E]/g, "."),
        hex: cleanHex
      });
    }
  }

  // C char array syntax: unsigned char key[] = { 0x4b, 0x37, ... } or "K7mQ2pL9"
  const cHexMatch = scriptText.match(/char\s+\w+\[\]\s*=\s*\{([0-9a-fx,\s]+)\}/i);
  if (cHexMatch) {
    const bytes = cHexMatch[1].split(",").map((s) => parseInt(s.trim(), 16)).filter((n) => !isNaN(n));
    if (bytes.length > 0) {
      keys.push({
        source: "C Hex Array",
        bytes: bytes,
        ascii: String.fromCharCode(...bytes),
        hex: Buffer.from(bytes).toString("hex")
      });
    }
  }

  return keys;
}

// 3. Automated Base64 Unpacker
export function unpackBase64(text) {
  const b64Regex = /(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;
  const matches = [...text.matchAll(b64Regex)].map((m) => m[0]);
  const decoded = [];

  for (const match of matches) {
    try {
      const buf = Buffer.from(match, "base64");
      const str = buf.toString("utf-8");
      // Filter printable ASCII
      if (/^[\x20-\x7E\r\n\t]+$/.test(str) && str.length > 15) {
        decoded.push({ originalB64: match.slice(0, 30) + "...", decodedText: str });
      }
    } catch (e) {}
  }
  return decoded;
}

// 4. MSHTA & PowerShell Behavioral Parser
export function parseScriptBehavior(scriptText) {
  const findings = {
    scheduledTasks: [],
    comObjects: [],
    pInvokeMethods: [],
    downloadUrls: [],
    evasionFlags: []
  };

  // Scheduled task registrations
  const schMatch = scriptText.match(/schtasks\s+\/Create\s+\/TN\s+([^\s]+)/i);
  if (schMatch) {
    findings.scheduledTasks.push(schMatch[1].replace(/['"]/g, ""));
  }
  const taskNameVar = scriptText.match(/\$tn\s*=\s*['"]([^'"]+)['"]/i);
  if (taskNameVar) {
    findings.scheduledTasks.push(taskNameVar[1]);
  }

  // COM Objects
  const comMatches = [...scriptText.matchAll(/New-Object\s+-ComObject\s+['"]?([^'"\s]+)['"]?|ActiveXObject\(['"]([^'"]+)['"]\)/gi)];
  comMatches.forEach((m) => {
    const obj = m[1] || m[2];
    if (obj && !findings.comObjects.includes(obj)) findings.comObjects.push(obj);
  });

  // P/Invoke Win32 APIs
  const apis = ["VirtualAlloc", "VirtualProtect", "CreateThread", "WriteProcessMemory", "QueueUserAPC", "NtMapViewOfSection", "WaitForSingleObject"];
  apis.forEach((api) => {
    if (new RegExp(api, "i").test(scriptText) && !findings.pInvokeMethods.includes(api)) {
      findings.pInvokeMethods.push(api);
    }
  });

  // Download URLs
  const urlMatches = [...scriptText.matchAll(/https?:\/\/[^\s'")]+/gi)].map((m) => m[0]);
  urlMatches.forEach((u) => {
    if (!findings.downloadUrls.includes(u)) findings.downloadUrls.push(u);
  });

  // Evasion Flags
  if (/Settings\.Hidden\s*=\s*\$true/i.test(scriptText)) findings.evasionFlags.push("Scheduled Task Hidden Property ($true)");
  if (/-EP\s+Bypass/i.test(scriptText)) findings.evasionFlags.push("PowerShell ExecutionPolicy Bypass");
  if (/-W\s+Hidden/i.test(scriptText)) findings.evasionFlags.push("PowerShell Hidden Window Style");

  return findings;
}

// 5. Automated Multi-stage Deobfuscation Pipeline
export function analyzeAndDeobfuscateFiles(files) {
  const deobfResults = {
    recoveredKeys: [],
    decryptedArtifacts: [],
    scriptBehaviors: [],
    decodedBase64: []
  };

  // Pass 1: Extract Keys and Behaviors from Scripts
  for (const file of files) {
    const keys = extractXORKeysFromScript(file.content);
    if (keys.length > 0) {
      deobfResults.recoveredKeys.push(...keys);
    }

    const behavior = parseScriptBehavior(file.content);
    if (behavior.scheduledTasks.length > 0 || behavior.pInvokeMethods.length > 0 || behavior.comObjects.length > 0) {
      deobfResults.scriptBehaviors.push({ filename: file.filename, ...behavior });
    }

    const b64 = unpackBase64(file.content);
    if (b64.length > 0) {
      deobfResults.decodedBase64.push({ filename: file.filename, entries: b64 });
    }
  }

  // Pass 2: Decrypt Binary / Dat Files & Inline Hex Payloads using Recovered Keys
  if (deobfResults.recoveredKeys.length > 0) {
    for (const file of files) {
      // Inline Hex Data in Scripts
      const inlineHexMatch = file.content.match(/\$(?:encryptedHexData|cipherHexData|hexData)\s*=\s*(?:@'|@"|'|")([\s\S]*?)(?:'@|"@|'|")/i);
      if (inlineHexMatch) {
        const cleanCipherHex = inlineHexMatch[1].replace(/[^0-9a-fA-F]/g, "");
        if (cleanCipherHex.length >= 32) {
          const cipherBuffer = Buffer.from(cleanCipherHex, "hex");
          for (const key of deobfResults.recoveredKeys) {
            const decrypted = decryptXOR(cipherBuffer, key.bytes);
            if (decrypted) {
              const isPE = decrypted.slice(0, 2).toString() === "MZ";
              const hexHead = decrypted.slice(0, 16).toString("hex");
              const utf8Str = decrypted.toString("utf-8");
              deobfResults.decryptedArtifacts.push({
                sourceFile: `${file.filename} (Inline Hex Payload)`,
                keyUsed: key.ascii,
                keyHex: key.hex,
                decryptedLength: decrypted.length,
                isPEHeader: isPE,
                hexHeader: hexHead,
                previewString: utf8Str.slice(0, 300)
              });
            }
          }
        }
      }

      if (file.filename.endsWith(".dat") || file.filename.endsWith(".bin")) {
        const fileBuffer = Buffer.from(file.content, "binary");
        for (const key of deobfResults.recoveredKeys) {
          const decrypted = decryptXOR(fileBuffer, key.bytes);
          if (decrypted) {
            // Check for MZ / PE header or Shellcode markers
            const isPE = decrypted.slice(0, 2).toString() === "MZ";
            const hexHead = decrypted.slice(0, 16).toString("hex");
            deobfResults.decryptedArtifacts.push({
              sourceFile: file.filename,
              keyUsed: key.ascii,
              keyHex: key.hex,
              decryptedLength: decrypted.length,
              isPEHeader: isPE,
              hexHeader: hexHead,
              previewString: decrypted.toString("utf-8").replace(/[^\x20-\x7E\r\n\t]/g, ".").slice(0, 200)
            });
          }
        }
      }
    }
  }

  return deobfResults;
}
