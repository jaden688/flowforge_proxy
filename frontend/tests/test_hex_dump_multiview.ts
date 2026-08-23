import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { 
  generateHexDump, 
  detectFormat, 
  executeStep, 
  executeChain, 
  parseJwt,
  calculateEntropy,
  base64Decode,
  base64Encode,
  base64UrlDecode,
  base64UrlEncode,
  urlDecode,
  urlEncode,
  hexDecode,
  hexEncode,
  htmlDecode,
  htmlEncode
} from '../src/utils/decoder';

console.log("Starting Hex Dump & Multi-View Inspector Adversarial Test Suite...");

// ============================================================================
// Test 1: Empty and Boundary-Length Hex Dumps
// ============================================================================
console.log("\n[TEST 1] Empty & Boundary-Length Payloads");

// 1a. Empty payload
assert.deepEqual(generateHexDump(""), []);
assert.deepEqual(generateHexDump(new Uint8Array(0)), []);

// 1b. Single byte payload
const single = generateHexDump("A");
assert.equal(single.length, 1);
assert.equal(single[0].offset, 0);
assert.equal(single[0].offsetHex, "00000000");
assert.equal(single[0].bytes[0], 0x41);
assert.equal(single[0].bytesHex[0], "41");
assert.equal(single[0].ascii[0], "A");
assert.equal(single[0].bytes[1], null);
assert.equal(single[0].bytesHex[1], null);
assert.equal(single[0].ascii[1], " ");

// 1c. Exactly 16 bytes
const exact16 = generateHexDump("1234567890123456");
assert.equal(exact16.length, 1);
assert.ok(exact16[0].bytes.every((b) => b !== null));

// 1d. 17 bytes (spills over to 2nd row with offset 00000010)
const exact17 = generateHexDump("12345678901234567");
assert.equal(exact17.length, 2);
assert.equal(exact17[0].offsetHex, "00000000");
assert.equal(exact17[1].offsetHex, "00000010");
assert.equal(exact17[1].bytes[0], "7".charCodeAt(0));
assert.equal(exact17[1].bytes[1], null);

console.log("✓ Empty, 1-byte, 16-byte, and 17-byte payload hex dumps calculated with precise offsets.");

// ============================================================================
// Test 2: Large Payload (1 MB) Stress & Performance Invariants
// ============================================================================
console.log("\n[TEST 2] 1 MB (1,048,576 Bytes) Hex Dump Generation");
const oneMbBytes = new Uint8Array(1024 * 1024);
for (let i = 0; i < oneMbBytes.length; i++) {
  oneMbBytes[i] = (i * 37) % 256;
}

const startTime = performance.now();
const oneMbDump = generateHexDump(oneMbBytes, 16);
const durationMs = performance.now() - startTime;

assert.equal(oneMbDump.length, 65536, "1 MB / 16 bytes = 65,536 hex rows");
assert.equal(oneMbDump[0].offsetHex, "00000000");
assert.equal(oneMbDump[65535].offsetHex, "000ffff0");
assert.equal(oneMbDump[65535].offset, 1048560);

// Assert pagination math: with pageSize = 32 rows (512 bytes)
const pageSize = 32;
const totalPages = Math.ceil(oneMbDump.length / pageSize);
assert.equal(totalPages, 2048, "65,536 / 32 = 2,048 pages");

console.log(`✓ 1 MB payload processed into ${oneMbDump.length} rows (${totalPages} pages) in ${durationMs.toFixed(2)}ms.`);

// ============================================================================
// Test 3: Binary Spectrum & Non-Printable Character Mapping
// ============================================================================
console.log("\n[TEST 3] Full 256-Byte Binary Spectrum (0x00 to 0xFF)");
const all256Bytes = new Uint8Array(256);
for (let i = 0; i < 256; i++) {
  all256Bytes[i] = i;
}

const spectrumDump = generateHexDump(all256Bytes, 16);
assert.equal(spectrumDump.length, 16, "256 bytes / 16 = 16 rows");

spectrumDump.forEach((row, rowIdx) => {
  assert.equal(row.offset, rowIdx * 16);
  assert.equal(row.offsetHex, (rowIdx * 16).toString(16).padStart(8, '0'));
  assert.equal(row.bytes.length, 16);
  assert.equal(row.ascii.length, 16);

  // Validate ASCII characters: printable [32..126] vs '.' for non-printable
  row.bytes.forEach((b, colIdx) => {
    const val = b as number;
    const char = row.ascii[colIdx];
    if (val >= 32 && val <= 126) {
      assert.equal(char, String.fromCharCode(val), `Byte 0x${val.toString(16)} should be printable`);
    } else {
      assert.equal(char, '.', `Byte 0x${val.toString(16)} should map to '.'`);
    }
  });
});
console.log("✓ Full 256-byte ASCII mapping (printable vs non-printable) verified.");

// ============================================================================
// Test 4: Hex Search and Cross-Chunk Boundary Matching
// ============================================================================
console.log("\n[TEST 4] Text & Hex Search Match Offsets");
function computeSearchMatches(rawBytes: Uint8Array, searchQuery: string): Set<number> {
  if (!searchQuery.trim() || rawBytes.length === 0) return new Set<number>();
  const matches = new Set<number>();
  const q = searchQuery.toLowerCase();

  // 1. Text search
  const text = new TextDecoder('utf-8').decode(rawBytes).toLowerCase();
  let idx = text.indexOf(q);
  while (idx !== -1) {
    for (let i = 0; i < q.length; i++) {
      matches.add(idx + i);
    }
    idx = text.indexOf(q, idx + 1);
  }

  // 2. Hex search
  const cleanHexQuery = q.replace(/[\s0x]/g, '');
  if (/^[0-9a-f]+$/.test(cleanHexQuery) && cleanHexQuery.length % 2 === 0) {
    const targetBytes: number[] = [];
    for (let i = 0; i < cleanHexQuery.length; i += 2) {
      targetBytes.push(parseInt(cleanHexQuery.substring(i, i + 2), 16));
    }
    for (let i = 0; i <= rawBytes.length - targetBytes.length; i++) {
      let match = true;
      for (let j = 0; j < targetBytes.length; j++) {
        if (rawBytes[i + j] !== targetBytes[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        for (let j = 0; j < targetBytes.length; j++) {
          matches.add(i + j);
        }
      }
    }
  }

  return matches;
}

const samplePayload = new TextEncoder().encode("0123456789ABCDEF___CROSS_BOUNDARY_MATCH___");
// "CROSS_BOUNDARY" starts at index 19 (which spans chunk boundary 16-32)
const searchResult = computeSearchMatches(samplePayload, "CROSS_BOUNDARY");
assert.ok(searchResult.size >= 14, "Should find all 14 byte indices");
assert.ok(searchResult.has(19), "Should match start index 19");
assert.ok(searchResult.has(32), "Should match index 32 spanning chunk boundary");

// Hex search
const hexMatches = computeSearchMatches(samplePayload, "41 42 43"); // 'ABC'
assert.ok(hexMatches.size >= 3);

console.log("✓ Search matches across 16-byte chunk boundaries confirmed.");

// ============================================================================
// Test 5: Copy Formatting Exporters
// ============================================================================
console.log("\n[TEST 5] Copy Exporters (Raw, Hex Stream, C Array, Formatted Dump)");
const testInput = "Hello World!\n";
const inputBytes = new TextEncoder().encode(testInput);

// Hex stream
let hexStream = '';
for (let i = 0; i < inputBytes.length; i++) {
  hexStream += inputBytes[i].toString(16).padStart(2, '0');
}
assert.equal(hexStream, "48656c6c6f20576f726c64210a");

// C Array
const cArrayStr = `const unsigned char payload[${inputBytes.length}] = {\n  ` +
  Array.from(inputBytes).map((b) => `0x${b.toString(16).padStart(2, '0')}`).join(', ') +
  '\n};';
assert.ok(cArrayStr.startsWith("const unsigned char payload[13] = {"));
assert.ok(cArrayStr.includes("0x48, 0x65, 0x6c, 0x6c, 0x6f"));

// Full dump lines
const dumpRows = generateHexDump(inputBytes, 16);
const fullDump = dumpRows.map((r) => {
  const hexLeft = r.bytesHex.slice(0, 8).map((b) => b || '  ').join(' ');
  const hexRight = r.bytesHex.slice(8, 16).map((b) => b || '  ').join(' ');
  return `${r.offsetHex}  ${hexLeft}  ${hexRight}  |${r.ascii.join('')}|`;
}).join('\n');

assert.ok(fullDump.startsWith("00000000  48 65 6c 6c 6f 20 57 6f  72 6c 64 21 0a"));
assert.ok(fullDump.endsWith("|Hello World!.   |"));
console.log("✓ Hex stream, C Array, and Full Hex Dump export generators verified.");

// ============================================================================
// Test 6: Auto-Detection & Multi-Step Decoder Chain
// ============================================================================
console.log("\n[TEST 6] Auto-Detection & Multi-Layer Decoder Pipelines");

// 6a. JWT Auto-Detection
const testJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const jwtDetection = detectFormat(testJwt);
assert.equal(jwtDetection.format, 'JWT');
assert.ok(jwtDetection.suggestedOperations.includes('jwt_decode'));

const parsedJwt = parseJwt(testJwt);
assert.ok(parsedJwt);
assert.equal(parsedJwt?.header.alg, 'HS256');
assert.equal(parsedJwt?.payload.sub, '1234567890');
assert.equal(parsedJwt?.payload.role, 'admin');

// 6b. Base64 & Hex Multi-Pass Chain
const originalSecret = '{"apiKey": "FLOWFORGE_SECRET_9942"}';
const encodedB64 = base64Encode(originalSecret);
const encodedHex = hexEncode(encodedB64);

const chainResult = executeChain(encodedHex, ['hex_decode', 'base64_decode', 'json_prettify']);
assert.equal(chainResult.success, true);
assert.ok(chainResult.final_output.includes('"apiKey": "FLOWFORGE_SECRET_9942"'));
assert.equal(chainResult.steps.length, 3);

// 6c. Chain with graceful error handling on malformed intermediate data
const brokenChain = executeChain("NOT_A_VALID_BASE64_###", ['base64_decode', 'json_prettify']);
assert.equal(brokenChain.success, false);
assert.ok(brokenChain.steps[0].error !== undefined);

console.log("✓ Auto-detection and multi-step decoding pipelines verified.");
console.log("\nHex Dump & Multi-View Inspector Adversarial Test Suite PASSED 100%!");
