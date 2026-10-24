import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {root, readJSON, inventory, verifyInventory, requireThat, sha256, safeName} from './common.mjs';

const exclude = (name, directory) => name === '.git' || name === '.publication.json' || directory && (['build', '.cache', 'host/.cache', 'host/driver/target', 'node_modules'].includes(name) || /^\.kelft-(?:test|rebuild)-[a-f0-9]+$/.test(name));
export function sourceInventory(directory = root) {
  return inventory(directory, {exclude}).map(({path, sha256, bytes}) => ({path, sha256, bytes})).sort((a,b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}
export function checkSource(directory = root, {verify = false} = {}) {
  const manifest = readJSON(path.join(directory, '.publication.json'));
  requireThat(manifest.schema === 'kelft.public-export/1' && manifest.kind === 'compiler', 'Expected compiler export');
  if (verify) verifyInventory(directory, manifest.files, {exact: true, exclude});
  const observed = sourceInventory(directory);
  const modified = JSON.stringify(observed) !== JSON.stringify(manifest.files);
  manifest.files = observed;
  for (const row of manifest.files) {
    requireThat(!/^(src\/|docs\/references\/|native\/(evidence|certificates)\/)/.test(row.path), 'Private export path: ' + row.path);
    if (!/\.(kelft|mjs|md)$/.test(row.path)) continue;
    const text = fs.readFileSync(path.join(directory, row.path), 'utf8');
    if (row.path.endsWith('.kelft')) for (const match of text.matchAll(/^\s*import\s+"([^"]+)"/gm)) {
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(row.path), match[1])); safeName(resolved);
      requireThat(manifest.files.some(r => r.path === resolved), 'Missing import: ' + row.path + ' -> ' + resolved);
    }
    if (row.path.endsWith('.mjs')) for (const match of text.matchAll(/(?:from\s*|import\s*)['"](\.[^'"]+)['"]/g)) {
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(row.path), match[1])); safeName(resolved);
      requireThat(manifest.files.some(r => r.path === resolved), 'Missing build import: ' + resolved);
    }
    if (row.path.endsWith('.mjs')) for (const match of text.matchAll(/import\s*\(\s*['"](\.[^'"]+)['"]\s*\)/g)) {
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(row.path), match[1])); safeName(resolved);
      requireThat(manifest.files.some(r => r.path === resolved), 'Missing dynamic build import: ' + resolved);
    }
    if (row.path.endsWith('.md')) {
      for (const match of text.matchAll(/\[[^\]]*\]\(([^\s)]+)\)/g)) {
        if (/^https?:/.test(match[1])) {
          const url = new URL(match[1]);
          if (url.hostname.toLowerCase() === 'github.com' && url.pathname.split('/')[1]?.toLowerCase() === 'kelftlang') {
            requireThat(['kelft', 'kelft-spec', 'kelft-branding'].includes(url.pathname.split('/')[2]?.toLowerCase()), 'Unknown project documentation repository: ' + row.path);
          }
          continue;
        }
        if (/^(mailto:|#)/.test(match[1])) continue;
        const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(row.path), decodeURIComponent(match[1].split('#')[0]))); safeName(resolved);
        requireThat(manifest.files.some(r => r.path === resolved), 'Missing documentation link: ' + row.path + ' -> ' + resolved);
      }
    }
  }
  const release = readJSON(path.join(directory, 'release.json')), version = readJSON(path.join(directory, 'host/driver/release.json'));
  const licensing = readJSON(path.join(directory, 'licensing.json'));
  for (const name of [...licensing.dependencyInventories, ...licensing.licenseTexts]) requireThat(manifest.files.some(row => row.path === name), 'Missing licensing inventory: ' + name);
  requireThat(release.version === version.version && release.coreVersion === version.coreVersion && release.intentVersion === version.intentVersion, 'Host/compiler version mismatch');
  for (const profile of Object.values(release.targets)) requireThat(manifest.files.some(r => r.path === profile.entry), 'Missing compiler entry');
  const corpus = readJSON(path.join(directory, 'tests/conformance.json'));
  requireThat(manifest.files.some(row => row.path === 'tests/native-conformance.json'), 'Missing native conformance expectations');
  const selected = [];
  for (const group of ['positive', 'negative', 'negativeModules', 'runtime']) {
    requireThat(Array.isArray(corpus[group]), 'Missing conformance group: ' + group);
    for (const fixture of corpus[group]) {safeName(fixture.entry); selected.push(fixture.entry); requireThat(manifest.files.some(row => row.path === fixture.entry), 'Missing conformance fixture: ' + fixture.entry);}
  }
  const expectations = readJSON(path.join(directory, 'tests/native-conformance.json'));
  requireThat(expectations.schema === 'kelft.native-conformance/1' && Object.keys(expectations.cases).every(name => selected.includes(name)), 'Unknown native conformance expectations');
  return {status: 'passed', files: manifest.files.length, sourceInventorySHA256: sha256(JSON.stringify(manifest.files)), sourceDirty: manifest.sourceDirty || modified, inventoryVerified: verify};
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const args = process.argv.slice(2), verify = args.includes('--verify-inventory'), directories = args.filter(arg => arg !== '--verify-inventory');
  requireThat(directories.length <= 1 && !directories.some(arg => arg.startsWith('--')), 'Usage: check.mjs [DIRECTORY] [--verify-inventory]');
  console.log(JSON.stringify(checkSource(directories[0] ? path.resolve(directories[0]) : root, {verify})));
}
