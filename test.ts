import test from 'tape';
import { toBuffer } from './scripts/utils'
import {
  mnemonicToSeed,
  getHDNodeFromMnemonic,
  rlpEncode,
  keccak256
} from './scripts/crypto';

test('mnemonicToSeed returns 32-byte seed buffer', t => {
  const seed = mnemonicToSeed('test test test test test test test test test test test junk');
  t.ok(Buffer.isBuffer(seed), 'should return a buffer');
  t.equal(seed.length, 32, 'should be 32 bytes');
  t.end();
});

test('getHDNodeFromMnemonic derives key and chain code', t => {
  const node = getHDNodeFromMnemonic('test test test test test test test test test test test junk');
  t.ok(Buffer.isBuffer(node.key), 'should return a buffer as key');
  t.equal(node.key.length, 32, 'key should be 32 bytes');
  t.ok(Buffer.isBuffer(node.chainCode), 'should return a buffer as chainCode');
  t.equal(node.chainCode.length, 32, 'chainCode should be 32 bytes');
  t.end();
});

test('toBuffer handles various inputs', t => {
  const numBuf = toBuffer(255);
  t.equal(numBuf.toString('hex'), 'ff', 'number should convert to buffer');

  const bigIntBuf = toBuffer(BigInt(12345678901234567890n));
  t.ok(Buffer.isBuffer(bigIntBuf), 'bigint should convert to buffer');

  const buf = Buffer.from('abcd', 'hex');
  t.equal(toBuffer(buf), buf, 'buffer input should return itself');
  t.end();
});

test('rlpEncode encodes values', t => {
  const result = rlpEncode([0x0f, 0x00, Buffer.from('abcd', 'hex')]);
  t.ok(Buffer.isBuffer(result), 'RLP should return a buffer');
  t.ok(result.length > 0, 'encoded result should not be empty');
  t.end();
});

test('keccak256 hashes input correctly', t => {
  const hash = keccak256(Buffer.from('hello'));
  t.ok(Buffer.isBuffer(hash), 'should return a buffer');
  t.equal(hash.length, 32, 'should return 32-byte hash');
  t.end();
});
