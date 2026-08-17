import fs from "fs";
import { carvePEFromData } from "../Full Agent/core/pe_carver.mjs";

const files = ["aktcrypted.ps1", "crypted.ps1", "ojkcrypted.ps1"];

for (const fname of files) {
  const p = `F:/Full Agent/threat_intel_acquisitions/178_16_53_176_80/${fname}`;
  if (!fs.existsSync(p)) continue;
  const content = fs.readFileSync(p, "utf-8");

  const keyMarker = "$decryptionHexKey";
  const keyIdx = content.indexOf(keyMarker);
  const afterKey = content.slice(keyIdx);
  const k1 = afterKey.indexOf("@'");
  const k2 = afterKey.indexOf("'@");
  const hexKey = afterKey.slice(k1 + 2, k2).replace(/[^0-9a-fA-F]/g, "");

  const cipherMarker = "$encryptedHexData";
  const cipherIdx = content.indexOf(cipherMarker);
  const afterCipher = content.slice(cipherIdx);
  const c1 = afterCipher.indexOf("@'");
  const c2 = afterCipher.indexOf("'@");
  const cleanCipher = afterCipher.slice(c1 + 2, c2).replace(/[^0-9a-fA-F]/g, "");

  console.log(`\n================= ${fname} =================`);
  console.log(`Key Hex (${hexKey.length} chars):`, hexKey);
  console.log(`Cipher Hex (${cleanCipher.length} chars)`);

  const keyBuf = Buffer.from(hexKey, "hex");
  const cipherBuf = Buffer.from(cleanCipher, "hex");
  const decBuf = Buffer.alloc(cipherBuf.length);

  for (let i = 0; i < cipherBuf.length; i++) {
    decBuf[i] = cipherBuf[i] ^ keyBuf[i % keyBuf.length];
  }

  const decStr = decBuf.toString("utf-8");
  console.log("Decrypted Buffer Size:", decBuf.length);
  console.log("Decrypted Preview:", decStr.slice(0, 300));

  fs.writeFileSync(`F:/Full Agent/threat_intel_acquisitions/178_16_53_176_80/${fname}_dec.txt`, decBuf);

  // Check for PE inside
  const carved = await carvePEFromData(decBuf, fname);
  console.log("Carved from buffer:", carved);

  const carvedFromStr = await carvePEFromData(decStr, fname);
  console.log("Carved from string:", carvedFromStr);
}
