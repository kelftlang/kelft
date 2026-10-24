import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import zlib from 'node:zlib';
import {tarGzip, zip} from '../scripts/archive.mjs';
import {inventory, verifyInventory, safeName, sha256, json, options, newDirectory} from '../scripts/common.mjs';
import {verifySeed} from '../scripts/seed.mjs';

function scratch(t) {const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kelft-alpha-test-')); t.after(() => fs.rmSync(dir, {recursive: true})); return dir;}
test('archive bytes reproduce and ZIP members retain names, payloads and UNIX modes', () => {
  const rows = [{path: 'bin/kelft.exe', data: Buffer.from('native image'), mode: 0o755}, {path: 'docs/readme.md', data: Buffer.from('public source'), mode: 0o644}];
  assert.deepEqual(tarGzip(rows), tarGzip(rows)); assert.deepEqual(zip(rows), zip(rows));
  const tar = zlib.gunzipSync(tarGzip(rows)); assert.equal(tar.toString('ascii', 0, 14), 'bin/kelft.exe\0'); assert.equal(tar.toString('ascii', 512, 524), 'native image');
  const bytes = zip(rows); let at = 0;
  for (const row of rows) {assert.equal(bytes.readUInt32LE(at), 0x04034b50); const size = bytes.readUInt32LE(at + 18), length = bytes.readUInt16LE(at + 26); assert.equal(bytes.toString('utf8', at + 30, at + 30 + length), row.path); assert.deepEqual(zlib.inflateRawSync(bytes.subarray(at + 30 + length, at + 30 + length + size)), row.data); at += 30 + length + size;}
  assert.equal(bytes.readUInt32LE(at), 0x02014b50);
  assert.throws(() => tarGzip([{path: '../escape', data: Buffer.alloc(0)}]), /Unsafe/);
});
test('seed verification rejects changed manifests, files, extras, missing inputs and another host', t => {
  const dir = scratch(t), pkg = path.join(dir, 'package'); fs.mkdirSync(pkg);
  for (const name of ['bin/kelft.exe', 'bin/kelft-boundary.exe', 'rootfs/compiler.exe', 'rootfs/control/toolchain.json']) {const file = path.join(pkg, name); fs.mkdirSync(path.dirname(file), {recursive: true}); fs.writeFileSync(file, name);}
  const manifest = {schema: 'kelft.bootstrap-seed/1', target: 'windows-x86_64', files: inventory(pkg), sources: {sha256: sha256('sources')}, maximum: {read: [], write: [], execute: true}, producer: {sourceRevision: 'a'.repeat(40)}, trust: 'initial-binary-trust'};
  const file = path.join(dir, 'seed.json'); fs.writeFileSync(file, json(manifest)); const digest = sha256(json(manifest));
  assert.equal(verifySeed(pkg, file, digest, manifest.target).files.length, 4);
  assert.throws(() => verifySeed(pkg, file, digest, 'linux-x86_64'), /mismatch/);
  fs.writeFileSync(path.join(pkg, 'extra'), 'unreviewed'); assert.throws(() => verifySeed(pkg, file, digest, manifest.target), /Uninventoried/); fs.unlinkSync(path.join(pkg, 'extra'));
  fs.writeFileSync(path.join(pkg, 'bin/kelft.exe'), 'changed'); assert.throws(() => verifySeed(pkg, file, digest, manifest.target), /Changed/);
  fs.appendFileSync(file, ' '); assert.throws(() => verifySeed(pkg, file, digest, manifest.target), /manifest changed/);
  // Git seeds carry their manifest and readiness metadata beside the payload.
  fs.writeFileSync(path.join(pkg,'bin/kelft.exe'),'bin/kelft.exe');
  manifest.schema='kelft.native-seed/1';manifest.files=manifest.files.map(row=>({...row,mode:row.path.endsWith('.exe')?0o755:0o644}));const nativeFile=path.join(pkg,'seed.json');fs.writeFileSync(nativeFile,json(manifest));fs.writeFileSync(path.join(pkg,'READY'),'prepared');
  const nativeDigest=sha256(json(manifest));assert.equal(verifySeed(pkg,nativeFile,nativeDigest,manifest.target).files.length,4);
  fs.writeFileSync(path.join(pkg,'extra'),'unreviewed');assert.throws(()=>verifySeed(pkg,nativeFile,nativeDigest,manifest.target),/Uninventoried/);fs.unlinkSync(path.join(pkg,'extra'));
  fs.writeFileSync(path.join(pkg,'bin/kelft-boundary.exe'),'changed');assert.throws(()=>verifySeed(pkg,nativeFile,nativeDigest,manifest.target),/Changed/);
});
test('inventories reject path aliases, missing members and file substitutions', t => {
  assert.equal(safeName('source/libzstd_1.5.5+dfsg2.orig.tar.xz'),'source/libzstd_1.5.5+dfsg2.orig.tar.xz');
  const dir = scratch(t); fs.writeFileSync(path.join(dir, 'file'), 'original'); const rows = inventory(dir);
  fs.writeFileSync(path.join(dir, 'file'), 'changed'); assert.throws(() => verifyInventory(dir, rows), /Changed/);
  for (const name of ['../escape', 'C:/absolute', '.git/config', 'NUL', 'foo/../bar', 'name.']) assert.throws(() => safeName(name), /Unsafe/);
  assert.throws(() => options(['--out', 'a', '--out', 'b'], ['--out']), /duplicate/);
  assert.throws(() => options(['--unknown', 'a'], ['--out']), /Unknown/);
});
test('inventories and output creation reject directory links', t => {
  const dir = scratch(t), outside = path.join(dir, 'outside'), source = path.join(dir, 'source'); fs.mkdirSync(outside); fs.mkdirSync(source);
  try {fs.symlinkSync(outside, path.join(source, 'linked'), process.platform === 'win32' ? 'junction' : 'dir');}
  catch (error) {if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error.code)) {t.skip('OS does not permit symlink creation'); return;} throw error;}
  assert.throws(() => inventory(source), /Symlink/);
  assert.throws(() => newDirectory(path.join(source, 'linked', 'output')), /Symlink output/);
  assert.equal(fs.existsSync(path.join(outside, 'output')), false);
});
