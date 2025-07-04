import crypto from 'crypto';
import { ec as EC } from 'elliptic';
import Keccak from 'keccak';
import { toBuffer } from './utils';

// --- BIP39 seed derivation ---
export function mnemonicToSeed(mnemonic: string, passphrase = ''): Buffer {
  return crypto.pbkdf2Sync(
    Buffer.from(mnemonic, 'utf8'),
    Buffer.from('mnemonic' + passphrase, 'utf8'),
    2048,
    64,
    'sha512'
  ).slice(0, 32);
}

// --- BIP32-like HD wallet key derivation ---
export function deriveHDNode(
  rootKey: Buffer,
  rootChainCode: Buffer,
  path: string
): { key: Buffer; chainCode: Buffer } {
  const ec = new EC('secp256k1');
  let key = rootKey;
  let chainCode = rootChainCode;

  const segments = path
    .split('/')
    .slice(1)
    .map(seg => {
      const hardened = seg.endsWith("'");
      const index = parseInt(seg.replace("'", ""), 10);
      return hardened ? index + 0x80000000 : index;
    });

  for (const index of segments) {
    const hardened = index >= 0x80000000;
    const data = hardened
      ? Buffer.concat([Buffer.alloc(1, 0), key])
      : Buffer.from(ec.keyFromPrivate(key).getPublic(false, 'array'));

    const indexBuf = Buffer.alloc(4);
    indexBuf.writeUInt32BE(index, 0);
    const I = crypto.createHmac('sha512', chainCode).update(Buffer.concat([data, indexBuf])).digest();

    const IL = I.slice(0, 32);
    const IR = I.slice(32);

    const ki = Buffer.from(
      ec.keyFromPrivate(IL).priv
        .add(ec.keyFromPrivate(key).priv)
        .mod(ec.curve.n)
        .toArray('be', 32)
    );

    key = ki;
    chainCode = IR;
  }

  return { key, chainCode };
}

export function getHDNodeFromMnemonic(m: string, path = `m/44'/60'/0'/0/0`) {
  const seed = mnemonicToSeed(m);
  const I = crypto.createHmac('sha512', 'Bitcoin seed').update(seed).digest();
  const rootKey = I.slice(0, 32);
  const rootChainCode = I.slice(32);
  return deriveHDNode(rootKey, rootChainCode, path);
}

/**
 * Sanitizes input to be RLP-safe: removes leading zeroes from integers/bigints,
 * returns empty buffer for zero, passes buffers untouched.
 */
export function sanitizeRlpInput(value: number | bigint | Buffer | string): Buffer {
  if (Buffer.isBuffer(value)) return value;

  if (typeof value === 'string') {
    const stripped = value.replace(/^0x/, '');
    return Buffer.from(stripped.length % 2 === 0 ? stripped : '0' + stripped, 'hex');
  }

  if (typeof value === 'number' || typeof value === 'bigint') {
    const big = BigInt(value);
    if (big === 0n) return Buffer.alloc(0);

    let hex = big.toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;
    return Buffer.from(hex, 'hex');
  }

  throw new TypeError(`Unsupported RLP input type: ${typeof value}`);
}

// --- Minimal RLP encoding ---
export function rlpEncode(input: any[]): Buffer {
  const encodeItem = (item: any): Buffer => {
    const buf = sanitizeRlpInput(item);
    if (buf.length === 1 && buf[0] < 0x80) return buf;

    const len = buf.length;
    if (len < 56) return Buffer.concat([Buffer.from([0x80 + len]), buf]);

    const lenBuf = sanitizeRlpInput(len);
    return Buffer.concat([Buffer.from([0xb7 + lenBuf.length]), lenBuf, buf]);
  };

  const encoded = input.map(encodeItem);
  const joined = Buffer.concat(encoded);

  if (joined.length < 56) return Buffer.concat([Buffer.from([0xc0 + joined.length]), joined]);

  const lbuf = sanitizeRlpInput(joined.length);
  return Buffer.concat([Buffer.from([0xf7 + lbuf.length]), lbuf, joined]);
}


// --- Keccak256 hash from buffer ---
export function keccak256(buf: Buffer): Buffer {
  return Keccak('keccak256').update(buf).digest();
}