import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {readJSON, sha256, requireThat, verifyInventory, hostTarget, options} from './common.mjs';
import {seedPayloadReader} from './seed-payload.mjs';

export function verifySeed(directory, manifestFile, expectedSHA256, target = hostTarget()) {
  requireThat(/^sha256:[a-f0-9]{64}$/.test(expectedSHA256), 'Supply an independently reviewed seed manifest SHA-256');
  const bytes = fs.readFileSync(manifestFile); requireThat(sha256(bytes) === expectedSHA256, 'Seed manifest changed');
  const manifest = JSON.parse(bytes);
  requireThat(['kelft.bootstrap-seed/1','kelft.native-seed/1'].includes(manifest.schema) && manifest.target === target, 'Seed host/contract mismatch');
  if(manifest.schema==='kelft.native-seed/1')seedPayloadReader(directory,manifest);
  else verifyInventory(directory, manifest.files);
  requireThat(manifest.sources?.sha256 && manifest.maximum && manifest.producer && manifest.trust === 'initial-binary-trust', 'Incomplete seed provenance');
  const suffix = target.startsWith('windows-') ? '.exe' : '';
  for (const name of ['bin/kelft' + suffix, 'bin/kelft-boundary' + suffix, 'rootfs/compiler' + suffix, 'rootfs/control/toolchain.json']) requireThat(manifest.files.some(r => r.path === name), 'Seed missing required input: ' + name);
  return manifest;
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const args = options(process.argv.slice(2), ['--package', '--manifest', '--sha256', '--sources']);
  const seed = verifySeed(path.resolve(args.package), path.resolve(args.manifest), args.sha256);
  requireThat(args.sources && sha256(fs.readFileSync(args.sources)) === seed.sources.sha256, 'Seed source archive changed or missing');
  console.log(JSON.stringify({status: 'verified', target: seed.target, files: seed.files.length, trust: seed.trust, releaseEligible: false}));
}
