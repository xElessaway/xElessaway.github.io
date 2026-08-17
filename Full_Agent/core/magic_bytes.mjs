import { Buffer } from "node:buffer";

/**
 * Deep File Typing, Magic Byte Scanner & Multi-Layer Obfuscation Classifier
 */

export function detectMagicBytes(fileBuffer) {
  if (!fileBuffer || fileBuffer.length < 4) return { type: "Unknown", description: "Empty / Incomplete buffer" };

  const hexHead = fileBuffer.slice(0, 16).toString("hex").toUpperCase();
  const asciiHead = fileBuffer.slice(0, 16).toString("ascii");

  // 1. Windows PE Executables / Drivers / DLLs
  if (asciiHead.startsWith("MZ")) {
    return {
      type: "Windows PE (Portable Executable)",
      mime: "application/x-dosexec",
      hexSignature: hexHead.slice(0, 8),
      details: "Windows Executable / Dynamic Link Library / Kernel Driver (.sys/.dll/.exe)"
    };
  }

  // 2. Linux ELF Binaries
  if (hexHead.startsWith("7F454C46")) {
    const is64 = fileBuffer[4] === 2;
    const arch = is64 ? "x86_64" : "x86/ARM/MIPS";
    return {
      type: `Linux ELF Binary (${arch})`,
      mime: "application/x-executable",
      hexSignature: "7F454C46",
      details: `Executable and Linkable Format binary compiled for Linux (${arch})`
    };
  }

  // 3. Windows Shortcut LNK
  if (hexHead.startsWith("4C00000001140200")) {
    return {
      type: "Windows Shell Link (LNK)",
      mime: "application/x-ms-shortcut",
      hexSignature: "4C00000001140200",
      details: "Windows Shortcut used for phishing lure initial access"
    };
  }

  // 4. ZIP / Office OpenXML / JAR / APK
  if (hexHead.startsWith("504B0304") || hexHead.startsWith("504B0506")) {
    return {
      type: "ZIP / Office Malicious Document / APK",
      mime: "application/zip",
      hexSignature: "504B0304",
      details: "Compressed archive container (ZIP/DOCX/XLSM/JAR)"
    };
  }

  // 5. RAR Archives
  if (hexHead.startsWith("526172211A07")) {
    return {
      type: "RAR Archive",
      mime: "application/x-rar",
      hexSignature: "52617221",
      details: "Multi-file compressed RAR archive"
    };
  }

  // 6. 7-Zip Archive
  if (hexHead.startsWith("377ABCAF271C")) {
    return {
      type: "7-Zip Archive",
      mime: "application/x-7z-compressed",
      hexSignature: "377ABCAF271C",
      details: "High-compression 7z archive container"
    };
  }

  // 7. ISO 9660 Disk Image
  if (fileBuffer.length > 32774 && fileBuffer.slice(32769, 32774).toString("ascii") === "CD001") {
    return {
      type: "ISO 9660 Disk Image Lure",
      mime: "application/x-iso9660-image",
      hexSignature: "CD001",
      details: "Optical disk image container used for MotW evasion"
    };
  }

  // 8. GZIP Compressed Stream
  if (hexHead.startsWith("1F8B")) {
    return {
      type: "GZIP Compressed Stream",
      mime: "application/gzip",
      hexSignature: "1F8B",
      details: "Gzip payload stream"
    };
  }

  // 9. Java Bytecode
  if (hexHead.startsWith("CAFEBABE")) {
    return {
      type: "Java Class Bytecode / Mach-O",
      mime: "application/java-vm",
      hexSignature: "CAFEBABE",
      details: "Compiled Java class or Mach-O Fat Binary"
    };
  }

  // 10. PDF Document
  if (asciiHead.startsWith("%PDF")) {
    return {
      type: "PDF Document",
      mime: "application/pdf",
      hexSignature: "25504446",
      details: "Portable Document Format (potential lure or embedded JS exploit)"
    };
  }

  return {
    type: "Raw Data / Unknown Format",
    mime: "application/octet-stream",
    hexSignature: hexHead.slice(0, 8),
    details: "Unclassified binary sequence or encrypted shellcode payload"
  };
}

/**
 * Scan Scripts & Binaries for Multi-Layer Obfuscation Patterns
 */
export function identifyObfuscationTechniques(text, filename) {
  const techniques = [];

  // A. XOR Encryption
  if (/\b(?:bxor|\^|\-bxor|xorKey|XORData)\b/i.test(text)) {
    techniques.push({
      technique: "XOR Obfuscation / Byte Flipping",
      mitre: "T1140 - Deobfuscate/Decode Files or Information",
      evidence: "XOR decryption operator or key array identified."
    });
  }

  // B. RC4 Stream Cipher
  if (/range\(256\)|\[byte\[\]\]\(0\.\.255\)|S-Box|key scheduling/i.test(text)) {
    techniques.push({
      technique: "RC4 Stream Cipher Engine",
      mitre: "T1027.013 - Encrypted/Encoded File: RC4",
      evidence: "S-Box permutation (0..255) array key-scheduling loop detected."
    });
  }

  // C. AES/DES Symmetric Crypto
  if (/RijndaelManaged|AesManaged|AES\.new|CipherMode\.CBC|CryptoJS\.AES/i.test(text)) {
    techniques.push({
      technique: "AES Block Cipher Cryptor",
      mitre: "T1027 - Obfuscated/Encrypted Files",
      evidence: "AES/Rijndael initialization vectors and cipher mode instances."
    });
  }

  // D. Base64 & Nested Encoding
  if (/FromBase64String|b64decode|atob\(|base64_decode/i.test(text)) {
    techniques.push({
      technique: "Base64 Encoding Layer",
      mitre: "T1027 - Obfuscated/Encrypted Files",
      evidence: "Native Base64 decoding primitives and stream decoders."
    });
  }

  // E. Dynamic Assembly Loading & P/Invoke
  if (/VirtualAlloc|Marshal\.Copy|GetProcAddress|LoadLibrary|QueueUserAPC/i.test(text)) {
    techniques.push({
      technique: "Dynamic Win32 API Resolving / Shellcode Loader",
      mitre: "T1106 - Native API / T1055 - Process Injection",
      evidence: "Low-level memory management and thread execution APIs."
    });
  }

  // F. Gzip / Deflate Stream Decompression
  if (/GZipStream|DeflateStream|zlib\.decompress/i.test(text)) {
    techniques.push({
      technique: "GZIP Compressed In-Memory Payload",
      mitre: "T1140 - Deobfuscate/Decode Files or Information",
      evidence: "MemoryStream decompression stream pipeline identified."
    });
  }

  // G. String Concatenation & Character Arrays
  if (/\[char\[\]\]@\(|String\.fromCharCode|ChrW\(|Chr\(/i.test(text)) {
    techniques.push({
      technique: "Character Array Evasion (Anti-AV Heuristics)",
      mitre: "T1027.002 - Software Packing",
      evidence: "Dynamic character code concatenation hiding commands."
    });
  }

  return techniques;
}
