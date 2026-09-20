// Independent format implementation using Node.js/OpenSSL; synthetic test keys only.
const crypto = require('node:crypto');
const fs = require('node:fs');
const request = JSON.parse(fs.readFileSync(0, 'utf8'));
const store = request.keystore;
const c = store.crypto;
const p = c.kdfparams || c;
const key = c.kdf === 'pbkdf2'
  ? crypto.pbkdf2Sync(request.password, Buffer.from(p.salt, 'hex'), p.c, p.dklen, 'sha256')
  : crypto.scryptSync(request.password, Buffer.from(p.salt, 'hex'), p.dklen,
      {N: p.n, r: p.r, p: p.p, maxmem: 64 * 1024 * 1024});
const authenticated = store.version === 5;
const params = c.kdf === 'pbkdf2'
  ? {kdf: c.kdf, dklen: p.dklen, c: p.c, prf: p.prf, salt: p.salt}
  : {kdf: c.kdf, dklen: p.dklen, n: p.n, p: p.p, r: p.r, salt: p.salt};
const aad = Buffer.from(JSON.stringify(['crypto-keystore', store.version, store.id,
  store.chain, c.cipher, params]));
const iv = Buffer.from(c.cipherparams.iv, 'hex');
if (request.operation === 'decrypt') {
  const cipher = crypto.createDecipheriv(c.cipher, key.subarray(0, authenticated ? 32 : 16), iv);
  if (authenticated) {
    cipher.setAAD(aad);
    cipher.setAuthTag(Buffer.from(c.mac, 'hex'));
  }
  const plaintext = Buffer.concat([cipher.update(Buffer.from(c.ciphertext, 'hex')), cipher.final()]);
  process.stdout.write(JSON.stringify({plaintext: plaintext.toString('hex')}));
} else {
  if (!authenticated) throw new Error('Independent encryption requires v5');
  const cipher = crypto.createCipheriv(c.cipher, key.subarray(0, 32), iv);
  cipher.setAAD(aad);
  c.ciphertext = Buffer.concat([cipher.update(Buffer.from(request.plaintext, 'hex')), cipher.final()]).toString('hex');
  c.mac = cipher.getAuthTag().toString('hex');
  process.stdout.write(JSON.stringify(store));
}
