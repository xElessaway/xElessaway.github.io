import { exec } from "node:child_process";
import { promisify } from "node:util";
import { resolve } from "node:path";
import { detectMagicBytes, identifyObfuscationTechniques } from "./magic_bytes.mjs";

const execAsync = promisify(exec);

/**
 * Windows Forensics & Linux Reverse Engineering Bridge
 */

// 1. Standalone LNK Binary Parser
export function parseLnkBinary(buffer) {
  try {
    if (!buffer || buffer.length < 76) return null;
    const headerSize = buffer.readUInt32LE(0);
    if (headerSize !== 76) return null;

    const flags = buffer.readUInt32LE(20);
    const hasLinkTargetIDList = (flags & 0x01) !== 0;
    const hasLinkInfo = (flags & 0x02) !== 0;
    const hasName = (flags & 0x04) !== 0;
    const hasRelativePath = (flags & 0x08) !== 0;
    const hasWorkingDir = (flags & 0x10) !== 0;
    const hasArguments = (flags & 0x20) !== 0;
    const hasIconLocation = (flags & 0x40) !== 0;
    const isUnicode = (flags & 0x80) !== 0;

    let offset = 76;
    if (hasLinkTargetIDList && offset + 2 <= buffer.length) {
      const idListSize = buffer.readUInt16LE(offset);
      offset += 2 + idListSize;
    }

    if (hasLinkInfo && offset + 4 <= buffer.length) {
      const linkInfoSize = buffer.readUInt32LE(offset);
      offset += linkInfoSize;
    }

    function readStringData() {
      if (offset + 2 > buffer.length) return "";
      const strLen = buffer.readUInt16LE(offset);
      offset += 2;
      let str = "";
      if (isUnicode) {
        const byteLen = strLen * 2;
        if (offset + byteLen <= buffer.length) {
          str = buffer.toString("utf16le", offset, offset + byteLen);
          offset += byteLen;
        }
      } else {
        if (offset + strLen <= buffer.length) {
          str = buffer.toString("ascii", offset, offset + strLen);
          offset += strLen;
        }
      }
      return str;
    }

    const description = hasName ? readStringData() : "";
    const relativePath = hasRelativePath ? readStringData() : "";
    const workingDir = hasWorkingDir ? readStringData() : "";
    const commandArgs = hasArguments ? readStringData() : "";
    const iconLocation = hasIconLocation ? readStringData() : "";

    const rawAscii = buffer.toString("ascii");
    const cmdMatch = rawAscii.match(/(?:cmd\.exe|powershell\.exe|mshta\.exe|wscript\.exe|cscript\.exe)[^\x00\r\n]+/i);

    return {
      type: "Windows Shell Link (LNK)",
      description,
      relativePath,
      workingDir,
      commandArgs: commandArgs || (cmdMatch ? cmdMatch[0] : "None"),
      iconLocation,
      flags: { hasArguments, hasIconLocation, isUnicode }
    };
  } catch (err) {
    return { error: `LNK parsing error: ${err.message}` };
  }
}

// 2. Eric Zimmerman LECmd Wrapper
export async function runLECmd(lnkFilePath) {
  try {
    const { stdout } = await execAsync(`LECmd.exe -f "${lnkFilePath}" --json .`, { timeout: 8000 });
    return { success: true, rawOutput: stdout };
  } catch (err) {
    return { success: false, reason: "LECmd CLI not found in PATH or failed execution." };
  }
}

// 3. WSL Linux Reverse Engineering Bridge
export async function runWSLInspection(filePath) {
  const results = {
    fileType: "Unknown",
    interestingStrings: [],
    networkIndicators: [],
    c2Patterns: [],
    xxdPreview: ""
  };

  try {
    const absPath = resolve(filePath).replace(/\\/g, "/");
    const wslPath = absPath.replace(/^([A-Za-z]):/, (_, drive) => `/mnt/${drive.toLowerCase()}`);

    // A. File command
    try {
      const { stdout: fileOut } = await execAsync(`wsl file -b "${wslPath}"`, { timeout: 6000 });
      results.fileType = fileOut.trim();
    } catch (e) {}

    // B. Strings extraction
    try {
      const { stdout: strOut } = await execAsync(`wsl strings -a -n 7 "${wslPath}" | head -n 60`, { timeout: 6000 });
      const rawLines = strOut.split("\n").map((s) => s.trim()).filter((s) => s.length > 6);
      results.interestingStrings = rawLines;

      // Extract IPs / URLs from strings
      rawLines.forEach((line) => {
        if (/https?:\/\//i.test(line)) results.networkIndicators.push(line);
        if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(line)) results.networkIndicators.push(line);
        if (/beacon|demon|c2|stage|inject|virtualalloc|sleep|pipe/i.test(line)) results.c2Patterns.push(line);
      });
    } catch (e) {}

    // C. Hex preview
    try {
      const { stdout: xxdOut } = await execAsync(`wsl xxd -p -l 32 "${wslPath}"`, { timeout: 6000 });
      results.xxdPreview = xxdOut.trim();
    } catch (e) {}

    return results;
  } catch (err) {
    return { error: `WSL inspection error: ${err.message}` };
  }
}

// 4. Comprehensive Multi-Layer Forensics
export async function performForensicAnalysis(files) {
  const forensicReport = {
    magicByteFindings: [],
    obfuscationTechniques: [],
    lnkArtifacts: [],
    binaryArtifacts: [],
    zimmermanLogs: []
  };

  for (const file of files) {
    const buf = Buffer.from(file.content, "binary");

    // 1. Magic Bytes Identification
    const magic = detectMagicBytes(buf);
    forensicReport.magicByteFindings.push({
      filename: file.filename,
      ...magic,
      sizeBytes: buf.length
    });

    // 2. Multi-Layer Obfuscation Classifier
    const obfTech = identifyObfuscationTechniques(file.content, file.filename);
    if (obfTech.length > 0) {
      forensicReport.obfuscationTechniques.push({
        filename: file.filename,
        techniques: obfTech
      });
    }

    // 3. LNK Forensics
    if (file.filename.endsWith(".lnk") || magic.hexSignature.startsWith("4C000000")) {
      const lnkData = parseLnkBinary(buf);
      if (lnkData) {
        forensicReport.lnkArtifacts.push({ filename: file.filename, ...lnkData });
      }

      if (file.path) {
        const zim = await runLECmd(file.path);
        if (zim.success) {
          forensicReport.zimmermanLogs.push({ filename: file.filename, data: zim.rawOutput });
        }
      }
    }

    // 4. WSL Binary Deep Reverse Engineering
    if (/\.(sys|bin|dat|exe|dll|so|elf|o|deb|tar|gz)$/i.test(file.filename) && file.path) {
      const wslData = await runWSLInspection(file.path);
      forensicReport.binaryArtifacts.push({
        filename: file.filename,
        fileType: wslData.fileType,
        magicType: magic.type,
        hexPreview: wslData.xxdPreview,
        c2Signatures: wslData.c2Patterns ? wslData.c2Patterns.slice(0, 10) : [],
        networkFound: wslData.networkIndicators ? wslData.networkIndicators.slice(0, 10) : [],
        stringsSample: wslData.interestingStrings.slice(0, 20)
      });
    }
  }

  return forensicReport;
}
