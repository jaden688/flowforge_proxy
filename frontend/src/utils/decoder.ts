import { 
  DecoderOperationType, 
  DetectedFormatType, 
  FormatDetectionResult, 
  JwtDecoded, 
  JwtExpiryStatus, 
  JwtHeader, 
  JwtPayload, 
  JwtSecurityFlag,
  DecoderStep,
  DecoderChainResult
} from '../types';

// ============================================================================
// Shannon Entropy Calculation
// ============================================================================

export function calculateEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const map: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    map[char] = (map[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const key in map) {
    const p = map[key] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

// ============================================================================
// Base64 & Base64URL Encoders / Decoders
// ============================================================================

export function base64Decode(str: string): string {
  const clean = str.trim();
  // Decode UTF-8 string from Base64
  const binaryString = atob(clean);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return new TextDecoder('utf-8').decode(bytes);
}

export function base64Encode(str: string): string {
  const bytes = new TextEncoder().encode(str);
  let binaryString = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binaryString += String.fromCharCode(bytes[i]);
  }
  return btoa(binaryString);
}

export function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return base64Decode(base64);
}

export function base64UrlEncode(str: string): string {
  const base64 = base64Encode(str);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ============================================================================
// URL Percent-Encoding Decoders / Encoders
// ============================================================================

export function urlDecode(str: string): string {
  try {
    return decodeURIComponent(str.replace(/\+/g, ' '));
  } catch {
    // Fallback: replace valid percent encodings individually
    return str.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => {
      try {
        return String.fromCharCode(parseInt(hex, 16));
      } catch {
        return `%${hex}`;
      }
    });
  }
}

export function urlEncode(str: string): string {
  return encodeURIComponent(str);
}

// ============================================================================
// Hex Encoders / Decoders & Hex Dump Formatting
// ============================================================================

export function hexEncode(str: string, separator = ' '): string {
  const bytes = new TextEncoder().encode(str);
  const hexParts: string[] = [];
  for (let i = 0; i < bytes.length; i++) {
    hexParts.push(bytes[i].toString(16).padStart(2, '0'));
  }
  return hexParts.join(separator);
}

export function hexDecode(hexStr: string): string {
  // Strip 0x, spaces, commas, newlines
  const clean = hexStr.replace(/0x/gi, '').replace(/[\s,:\-_]/g, '');
  if (clean.length % 2 !== 0) {
    throw new Error(`Invalid hex length: ${clean.length} characters (must be even)`);
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    const byteVal = parseInt(clean.substring(i, i + 2), 16);
    if (isNaN(byteVal)) {
      throw new Error(`Invalid hex byte at index ${i}: "${clean.substring(i, i + 2)}"`);
    }
    bytes[i / 2] = byteVal;
  }
  return new TextDecoder('utf-8').decode(bytes);
}

export interface HexDumpRow {
  offset: number;
  offsetHex: string;
  bytes: (number | null)[];
  bytesHex: (string | null)[];
  ascii: string[];
}

export function generateHexDump(input: string | Uint8Array, chunkSize = 16): HexDumpRow[] {
  let bytes: Uint8Array;
  if (typeof input === 'string') {
    bytes = new TextEncoder().encode(input);
  } else {
    bytes = input;
  }

  const rows: HexDumpRow[] = [];
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const rowBytes: (number | null)[] = [];
    const rowBytesHex: (string | null)[] = [];
    const rowAscii: string[] = [];

    for (let j = 0; j < chunkSize; j++) {
      const idx = i + j;
      if (idx < bytes.length) {
        const b = bytes[idx];
        rowBytes.push(b);
        rowBytesHex.push(b.toString(16).padStart(2, '0'));
        // Printable ASCII: 0x20 (space) to 0x7E (~)
        if (b >= 0x20 && b <= 0x7E) {
          rowAscii.push(String.fromCharCode(b));
        } else {
          rowAscii.push('.');
        }
      } else {
        rowBytes.push(null);
        rowBytesHex.push(null);
        rowAscii.push(' ');
      }
    }

    rows.push({
      offset: i,
      offsetHex: i.toString(16).padStart(8, '0'),
      bytes: rowBytes,
      bytesHex: rowBytesHex,
      ascii: rowAscii,
    });
  }

  return rows;
}

// ============================================================================
// HTML Entity Decoders / Encoders
// ============================================================================

export function htmlDecode(input: string): string {
  return input
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&nbsp;/g, ' ')
    .replace(/&copy;/g, '©')
    .replace(/&reg;/g, '®')
    .replace(/&#([0-9]{1,7});/g, (_, dec) => {
      try {
        return String.fromCodePoint(parseInt(dec, 10));
      } catch {
        return _;
      }
    })
    .replace(/&#x([0-9a-fA-F]{1,6});/g, (_, hex) => {
      try {
        return String.fromCodePoint(parseInt(hex, 16));
      } catch {
        return _;
      }
    });
}

export function htmlEncode(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ============================================================================
// JSON Prettify / Minify & ROT13
// ============================================================================

export function jsonPrettify(input: string): string {
  const parsed = JSON.parse(input);
  return JSON.stringify(parsed, null, 2);
}

export function jsonMinify(input: string): string {
  const parsed = JSON.parse(input);
  return JSON.stringify(parsed);
}

export function rot13(input: string): string {
  return input.replace(/[a-zA-Z]/g, (c) => {
    const code = c.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      return String.fromCharCode(((code - 65 + 13) % 26) + 65);
    }
    if (code >= 97 && code <= 122) {
      return String.fromCharCode(((code - 97 + 13) % 26) + 97);
    }
    return c;
  });
}

// ============================================================================
// JWT Claims Parsing & Security Audit
// ============================================================================

export function parseJwt(token: string): JwtDecoded | null {
  const trimmed = token.trim();
  const parts = trimmed.split('.');
  if (parts.length < 2 || parts.length > 3) {
    return null;
  }

  try {
    const headerJsonStr = base64UrlDecode(parts[0]);
    const payloadJsonStr = base64UrlDecode(parts[1]);

    const header: JwtHeader = JSON.parse(headerJsonStr);
    const payload: JwtPayload = JSON.parse(payloadJsonStr);
    const signatureRaw = parts[2] || '';

    // Calculate Expiry Status
    const nowSec = Math.floor(Date.now() / 1000);
    const expiry: JwtExpiryStatus = {
      is_expired: false,
      relative_expiry: 'No Expiration Set (Token Never Expires)',
      status_badge: 'NO_EXPIRY',
    };

    if (payload.exp !== undefined && typeof payload.exp === 'number') {
      const expDate = new Date(payload.exp * 1000);
      expiry.expires_at = expDate;
      const diffSec = payload.exp - nowSec;

      if (diffSec < 0) {
        expiry.is_expired = true;
        expiry.status_badge = 'EXPIRED';
        const absSec = Math.abs(diffSec);
        if (absSec < 60) {
          expiry.relative_expiry = `Expired ${absSec}s ago`;
        } else if (absSec < 3600) {
          expiry.relative_expiry = `Expired ${Math.floor(absSec / 60)}m ago`;
        } else if (absSec < 86400) {
          expiry.relative_expiry = `Expired ${Math.floor(absSec / 3600)}h ago`;
        } else {
          expiry.relative_expiry = `Expired ${Math.floor(absSec / 86400)}d ago`;
        }
      } else {
        expiry.is_expired = false;
        expiry.status_badge = 'ACTIVE';
        if (diffSec < 60) {
          expiry.relative_expiry = `Expires in ${diffSec}s`;
        } else if (diffSec < 3600) {
          expiry.relative_expiry = `Expires in ${Math.floor(diffSec / 60)}m`;
        } else if (diffSec < 86400) {
          expiry.relative_expiry = `Expires in ${Math.floor(diffSec / 3600)}h`;
        } else {
          expiry.relative_expiry = `Expires in ${Math.floor(diffSec / 86400)}d`;
        }
      }
    }

    if (payload.iat !== undefined && typeof payload.iat === 'number') {
      expiry.issued_at = new Date(payload.iat * 1000);
    }

    if (payload.nbf !== undefined && typeof payload.nbf === 'number') {
      expiry.not_before = new Date(payload.nbf * 1000);
      if (payload.nbf > nowSec) {
        expiry.status_badge = 'NOT_YET_VALID';
        expiry.relative_expiry = `Not valid until ${expiry.not_before.toLocaleTimeString()}`;
      }
    }

    // Security Flags & Vulnerability Checks
    const securityFlags: JwtSecurityFlag[] = [];

    // 1. None Algorithm Check
    const alg = (header.alg || '').toUpperCase();
    if (alg === 'NONE' || alg === '') {
      securityFlags.push({
        level: 'CRITICAL',
        title: 'Unsigned Token (alg: "none")',
        description: 'The token specifies algorithm "none" or no algorithm, which allows signature verification bypass on vulnerable backends.',
      });
    }

    // 2. RS256 / HS256 Confusion Risk
    if (alg === 'HS256') {
      securityFlags.push({
        level: 'MEDIUM',
        title: 'Symmetric HMAC Signing (HS256)',
        description: 'Uses symmetric HMAC-SHA256. If public key is mistakenly used as HMAC secret on RSA endpoints, token forgery is possible.',
      });
    }

    // 3. Missing Expiration Flag
    if (payload.exp === undefined) {
      securityFlags.push({
        level: 'HIGH',
        title: 'Missing Expiration (exp Claim)',
        description: 'Token has no expiration timestamp set. Once compromised or captured, it remains indefinitely replayable.',
      });
    }

    // 4. Token In-Flight but Expired
    if (expiry.is_expired) {
      securityFlags.push({
        level: 'HIGH',
        title: 'Expired Token In Traffic',
        description: `Token expired ${expiry.relative_expiry}. If accepted by backend, represents an authentication validation failure.`,
      });
    }

    // 5. Key ID (kid) Injection Risk
    if (header.kid && (header.kid.includes('../') || header.kid.includes('/') || header.kid.includes('\'') || header.kid.includes(';'))) {
      securityFlags.push({
        level: 'HIGH',
        title: 'Suspicious Key ID (kid) Header',
        description: `Header contains path traversal or SQL characters in kid: "${header.kid}". Potential kid directory traversal / SQL injection vector.`,
      });
    }

    // Identify Sensitive Claims
    const sensitiveClaims: { key: string; value: unknown; label: string }[] = [];
    const sensitiveKeys = ['role', 'roles', 'is_admin', 'isAdmin', 'admin', 'superuser', 'permissions', 'scope', 'email', 'sub', 'user_id', 'id', 'tenant_id', 'org_id'];

    Object.entries(payload).forEach(([k, v]) => {
      const lower = k.toLowerCase();
      if (sensitiveKeys.some(sk => sk.toLowerCase() === lower)) {
        let label = 'User Identity';
        if (lower.includes('role') || lower.includes('admin') || lower.includes('perm') || lower.includes('scope')) {
          label = 'Privilege / Authorization';
        } else if (lower.includes('tenant') || lower.includes('org')) {
          label = 'Multi-Tenant Context';
        }
        sensitiveClaims.push({ key: k, value: v, label });
      }
    });

    return {
      raw: trimmed,
      header_raw: parts[0],
      payload_raw: parts[1],
      signature_raw: signatureRaw,
      header,
      payload,
      signature_valid_format: parts.length === 3 && parts[2].length > 0,
      expiry,
      security_flags: securityFlags,
      sensitive_claims: sensitiveClaims,
    };
  } catch (err) {
    return null;
  }
}

// ============================================================================
// Auto-Detection Engine
// ============================================================================

export function detectFormat(rawInput: string): FormatDetectionResult {
  const input = rawInput.trim();
  if (!input) {
    return {
      format: 'PLAIN_TEXT',
      confidence: 1.0,
      label: 'Empty String',
      suggestedOperations: ['base64_encode', 'url_encode', 'hex_encode'],
    };
  }

  // 1. Check JWT Token
  if (/^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_=]*$/.test(input) && input.split('.').length >= 2) {
    try {
      const decoded = parseJwt(input);
      if (decoded && decoded.header && (decoded.header.alg !== undefined || decoded.header.typ !== undefined)) {
        return {
          format: 'JWT',
          confidence: 0.99,
          label: `JWT Token (${decoded.header.alg || 'none'})`,
          suggestedOperations: ['jwt_decode', 'base64url_decode'],
          preview: `Sub: ${decoded.payload.sub || 'none'}, Exp: ${decoded.expiry.relative_expiry}`,
        };
      }
    } catch {
      // Continue to next check
    }
  }

  // 2. Check JSON
  if ((input.startsWith('{') && input.endsWith('}')) || (input.startsWith('[') && input.endsWith(']'))) {
    try {
      JSON.parse(input);
      return {
        format: 'JSON',
        confidence: 0.96,
        label: 'JSON Document',
        suggestedOperations: ['json_prettify', 'json_minify', 'base64_encode', 'url_encode'],
      };
    } catch {
      // Continue
    }
  }

  // 3. Check XML / HTML
  if (input.startsWith('<') && input.endsWith('>') && (input.includes('</') || input.includes('/>') || input.startsWith('<?xml'))) {
    return {
      format: 'XML',
      confidence: 0.92,
      label: 'XML / HTML Markup',
      suggestedOperations: ['html_decode', 'html_encode', 'base64_encode'],
    };
  }

  // 4. Check HTML Entities
  if (/&[a-zA-Z]+;|&#[0-9]+;|&#x[0-9a-fA-F]+;/.test(input)) {
    return {
      format: 'HTML_ENTITIES',
      confidence: 0.90,
      label: 'HTML Entity Encoded',
      suggestedOperations: ['html_decode', 'url_decode'],
    };
  }

  // 5. Check URL Percent Encoding
  if (/%[0-9A-Fa-f]{2}/.test(input)) {
    return {
      format: 'URL_ENCODED',
      confidence: 0.88,
      label: 'URL Percent-Encoded',
      suggestedOperations: ['url_decode', 'base64_decode'],
    };
  }

  // 6. Check Hex Stream
  const hexClean = input.replace(/0x/gi, '').replace(/[\s,:\-_]/g, '');
  if (/^[0-9a-fA-F]+$/.test(hexClean) && hexClean.length >= 4 && hexClean.length % 2 === 0) {
    return {
      format: 'HEX_STREAM',
      confidence: 0.85,
      label: `Hex Stream (${hexClean.length / 2} bytes)`,
      suggestedOperations: ['hex_decode', 'hex_dump'],
    };
  }

  // 7. Check Base64 / Base64URL
  if (/^[A-Za-z0-9+/=_-]{8,}$/.test(input)) {
    try {
      const decoded = base64UrlDecode(input);
      // Check if decoded contains printable characters
      let printableCount = 0;
      for (let i = 0; i < decoded.length; i++) {
        const code = decoded.charCodeAt(i);
        if ((code >= 32 && code <= 126) || code === 10 || code === 13 || code === 9) {
          printableCount++;
        }
      }
      if (printableCount / decoded.length > 0.75) {
        return {
          format: input.includes('-') || input.includes('_') ? 'BASE64_URL' : 'BASE64',
          confidence: 0.82,
          label: input.includes('-') || input.includes('_') ? 'Base64URL Encoded' : 'Base64 Encoded',
          suggestedOperations: ['base64_decode', 'base64url_decode', 'jwt_decode'],
          preview: decoded.length > 40 ? decoded.substring(0, 40) + '...' : decoded,
        };
      }
    } catch {
      // Continue
    }
  }

  return {
    format: 'PLAIN_TEXT',
    confidence: 0.70,
    label: 'Plain Text',
    suggestedOperations: ['base64_encode', 'url_encode', 'hex_encode', 'rot13'],
  };
}

// ============================================================================
// Multi-Step Pipeline Executor
// ============================================================================

export function executeStep(input: string, op: DecoderOperationType): DecoderStep {
  const start = performance.now();
  const inputEntropy = calculateEntropy(input);
  let output = '';
  let error: string | undefined;

  try {
    switch (op) {
      case 'base64_decode':
        output = base64Decode(input);
        break;
      case 'base64_encode':
        output = base64Encode(input);
        break;
      case 'base64url_decode':
        output = base64UrlDecode(input);
        break;
      case 'base64url_encode':
        output = base64UrlEncode(input);
        break;
      case 'url_decode':
        output = urlDecode(input);
        break;
      case 'url_encode':
        output = urlEncode(input);
        break;
      case 'hex_decode':
        output = hexDecode(input);
        break;
      case 'hex_encode':
        output = hexEncode(input);
        break;
      case 'hex_dump':
        const rows = generateHexDump(input);
        output = rows.map(r => `${r.offsetHex}  ${r.bytesHex.map(b => b || '  ').join(' ')}  |${r.ascii.join('')}|`).join('\n');
        break;
      case 'html_decode':
        output = htmlDecode(input);
        break;
      case 'html_encode':
        output = htmlEncode(input);
        break;
      case 'json_prettify':
        output = jsonPrettify(input);
        break;
      case 'json_minify':
        output = jsonMinify(input);
        break;
      case 'rot13':
        output = rot13(input);
        break;
      case 'jwt_decode': {
        const jwt = parseJwt(input);
        if (!jwt) throw new Error('Input is not a valid JWT token structure (header.payload.signature)');
        output = JSON.stringify({
          header: jwt.header,
          payload: jwt.payload,
          signature: jwt.signature_raw,
          expiry: jwt.expiry,
          security_flags: jwt.security_flags,
        }, null, 2);
        break;
      }
      default:
        output = input;
    }
  } catch (err: any) {
    error = err.message || 'Operation failed';
    output = input;
  }

  const duration = performance.now() - start;
  const outputEntropy = calculateEntropy(output);

  return {
    id: Math.random().toString(36).substring(2, 9),
    operation: op,
    input,
    output,
    error,
    duration_ms: Number(duration.toFixed(2)),
    entropy_delta: Number((outputEntropy - inputEntropy).toFixed(3)),
  };
}

export function executeChain(initialInput: string, operations: DecoderOperationType[]): DecoderChainResult {
  let current = initialInput;
  const steps: DecoderStep[] = [];
  let allSuccess = true;

  for (const op of operations) {
    const step = executeStep(current, op);
    steps.push(step);
    if (step.error) {
      allSuccess = false;
      break;
    }
    current = step.output;
  }

  let jwtData: JwtDecoded | undefined;
  if (operations.includes('jwt_decode') || operations.length === 0) {
    const parsed = parseJwt(initialInput) || parseJwt(current);
    if (parsed) jwtData = parsed;
  }

  return {
    initial_input: initialInput,
    final_output: current,
    steps,
    success: allSuccess,
    jwt_data: jwtData,
  };
}
