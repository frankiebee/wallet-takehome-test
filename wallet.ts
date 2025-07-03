#!/usr/bin/env ts-node

import crypto from 'crypto';
import { ec as EC } from 'elliptic';
import Keccak from 'keccak';
import { parseArgs } from './utils'

// --- BIP39 seed derivation ---
function mnemonicToSeed(mnemonic: string, passphrase = ''): Buffer {
  return crypto.pbkdf2Sync(
    Buffer.from(mnemonic, 'utf8'),
    Buffer.from('mnemonic' + passphrase, 'utf8'),
    2048,
    64,
    'sha512'
  ).slice(0, 32);
}

// --- BIP32-like HD wallet key derivation ---
function deriveHDNode(
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

function getHDNodeFromMnemonic(m: string, path = `m/44'/60'/0'/0/0`) {
  const seed = mnemonicToSeed(m);
  const I = crypto.createHmac('sha512', 'Bitcoin seed').update(seed).digest();
  const rootKey = I.slice(0, 32);
  const rootChainCode = I.slice(32);
  return deriveHDNode(rootKey, rootChainCode, path);
}

// --- Utils ---
function toBuffer(v: number | bigint | Buffer): Buffer {
  if (typeof v === 'number') v = BigInt(v);
  if (typeof v === 'bigint') {
    if (v === 0n) return Buffer.alloc(0);
    let hex = v.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    return Buffer.from(hex, 'hex');
  }
  return v;
}

// --- Minimal RLP encoding ---
function rlpEncode(input: any[]): Buffer {
  const encodeItem = (item: any): Buffer => {
    const buf = toBuffer(item);
    if (buf.length === 1 && buf[0] < 0x80) return buf;
    const len = buf.length;
    if (len < 56) return Buffer.concat([Buffer.from([0x80 + len]), buf]);
    const lbuf = toBuffer(len);
    return Buffer.concat([Buffer.from([0xb7 + lbuf.length]), lbuf, buf]);
  };

  const output = input.map(encodeItem);
  const joined = Buffer.concat(output);
  if (joined.length < 56) return Buffer.concat([Buffer.from([0xc0 + joined.length]), joined]);
  const lbuf = toBuffer(joined.length);
  return Buffer.concat([Buffer.from([0xf7 + lbuf.length]), lbuf, joined]);
}

// --- Keccak256 hash ---
function keccak256(buf: Buffer): Buffer {
  return Keccak('keccak256').update(buf).digest();
}

// --- Main ---
(async () => {
  const argv = parseArgs();
  let mnemonic = argv.mnemonic ? argv.mnemonic : 'test test test test test test test test test test test junk';

  const node = getHDNodeFromMnemonic(
    'test test test test test test test test test test test junk'
  );
  const priv = node.key;
  const ec = new EC('secp256k1');
  const key = ec.keyFromPrivate(priv);

  const txData = [
    argv.nonce,
    BigInt(argv.gasPrice),
    argv.gasLimit,
    Buffer.from(argv.to.replace(/^0x/, ''), 'hex'),
    BigInt(Math.floor(argv.value * 1e18)),
    Buffer.alloc(0),
    argv.chainId,
    0,
    0
  ];

  const rlpBody = rlpEncode(txData);
  const hash = keccak256(rlpBody);
  const sig = key.sign(hash, { canonical: true });
  const v = BigInt(argv.chainId * 2 + 35 + sig.recoveryParam!);

  txData[6] = v;
  txData[7] = Buffer.from(sig.r.toArray('be', 32));
  txData[8] = Buffer.from(sig.s.toArray('be', 32));

  const raw = rlpEncode(txData).toString('hex');
  const txHash = keccak256(Buffer.from(raw, 'hex')).toString('hex');

  console.log('raw:', '0x' + raw);
  console.log('txHash:', '0x' + txHash);
})();

// For unit tests
module.exports = {
  mnemonicToSeed,
  getHDNodeFromMnemonic,
  toBuffer,
  rlpEncode,
  keccak256
};
