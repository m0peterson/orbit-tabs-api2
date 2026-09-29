import test from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, signToken, verifyPassword, verifyToken } from '../src/worker.js';

test('Cloudflare password hashes verify', async () => {
  const stored = await hashPassword('correct horse battery staple');
  assert.equal(await verifyPassword('correct horse battery staple', stored), true);
  assert.equal(await verifyPassword('incorrect password', stored), false);
});

test('Cloudflare password hashing stays within the Workers PBKDF2 limit', async () => {
  await assert.doesNotReject(() => hashPassword('ten-chars+'));
});

test('Cloudflare tokens reject tampering and expiry', async () => {
  const secret = 'a'.repeat(32);
  const token = await signToken({ sub: 'user-1' }, secret, 60);
  assert.equal((await verifyToken(token, secret)).sub, 'user-1');
  assert.equal(await verifyToken(`${token}x`, secret), null);
  assert.equal(await verifyToken(await signToken({ sub: 'x' }, secret, -1), secret), null);
});
