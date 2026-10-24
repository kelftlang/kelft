import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {root, readJSON, json, sha256, requireThat, inventory, verifyInventory, safeFile, newDirectory, options} from './common.mjs';
import {tarGzip, zip, writeSourceArchive} from './archive.mjs';
import {checkSource} from './check.mjs';

export async function packageBuild(buildDirectory, output, notices, directory = root) {
  const source = checkSource(directory, {verify: true}), release = readJSON(path.join(directory, 'release.json')), build = readJSON(path.join(buildDirectory, 'build.json'));
  requireThat(build.schema === 'kelft.public-build/1' && build.status === 'built' && build.phase === 'installed', 'An installed public build is required');
  requireThat(Object.hasOwn(release.targets, build.target) && build.version === release.version && build.sourceInventorySHA256 === source.sourceInventorySHA256, 'Build/source identity mismatch');
  requireThat(notices && fs.statSync(notices).isDirectory(), 'Supply reviewed dependency notices for the exact native closure');
  const packageRoot = path.join(buildDirectory, 'package'), files = inventory(packageRoot), windows = build.target.startsWith('windows-');
  verifyInventory(packageRoot, build.installedFiles);
  for (const row of files) requireThat(!/(^|\/)(engines|cross|\.kelft-targets)(\/|$)|engine-profiles/.test(row.path), 'Optional payload in native package: ' + row.path);
  const required = ['bin/kelft', 'bin/kelft-boundary', 'rootfs/compiler'].map(name => name + (windows ? '.exe' : ''));
  for (const name of required) requireThat(files.some(r => r.path === name), 'Missing installed file: ' + name);
  requireThat(sha256(fs.readFileSync(path.join(packageRoot, required[2]))) === build.compiler.sha256, 'Built compiler changed');
  const rows = files.map(r => ({path: r.path, file: safeFile(packageRoot, r.path), mode: windows ? /\.exe$/i.test(r.path) ? 0o755 : 0o644 : r.mode}));
  for (const name of ['LICENSE', 'LICENSE-MIT', 'LICENSE-APACHE', 'LICENSES/CC-BY-4.0.txt', 'LICENSES/MIT-0.txt', 'licensing.json', 'TRADEMARKS.md']) rows.push({path: 'licenses/kelft/' + name, file: safeFile(directory, name), mode: 0o644});
  const noticeRows = inventory(notices); requireThat(noticeRows.length > 0, 'Empty dependency notices');
  for (const row of noticeRows) rows.push({path: 'licenses/dependencies/' + row.path, file: safeFile(notices, row.path), mode: 0o644});
  rows.push({path: 'release.json', data: json(release), mode: 0o644});
  rows.push({path: 'README.md', file: safeFile(directory,'INSTALL.md'), mode: 0o644});
  rows.sort((a,b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  requireThat(new Set(rows.map(r => r.path.toLowerCase())).size === rows.length, 'Package path collision');
  output = newDirectory(output);
  const archive = 'kelft-v' + release.version + '-' + build.target + (windows ? '.zip' : '.tar.gz'), bytes = windows ? zip(rows) : tarGzip(rows);
  fs.writeFileSync(path.join(output, archive), bytes);
  const manifest = readJSON(path.join(directory, '.publication.json'));
  const assetFile = path.join(directory, 'bootstrap/assets.json'), modes = fs.existsSync(assetFile) ? new Map(readJSON(assetFile).files.map(row => ['bootstrap/' + row.path, row.mode])) : new Map();
  const sourceName = 'kelft-v' + release.version + '-source.tar.gz';
  const sourceArtifact=await writeSourceArchive([...manifest.files.map(r => ({...r,file:safeFile(directory,r.path),mode:modes.get(r.path)??(r.path==='bootstrap.sh'?0o755:0o644)})),{path:'.publication.json',file:path.join(directory,'.publication.json'),mode:0o644}].sort((a,b)=>a.path<b.path?-1:1),path.join(output,sourceName));
  const artifacts = [{file: archive, sha256: sha256(bytes), bytes: bytes.length}, {file:sourceArtifact.file,sha256:sourceArtifact.sha256,bytes:sourceArtifact.bytes}];
  const report = {schema: 'kelft.alpha-package/1', target: build.target, version: release.version, sourceInventorySHA256: source.sourceInventorySHA256, seedManifestSHA256: build.seedManifestSHA256, compiler: build.compiler, object: build.object, files: rows.map(r => {const bytes = r.data ?? fs.readFileSync(r.file); return {path: r.path, bytes: bytes.length, mode: r.mode, sha256: sha256(bytes)};}), artifacts, dependencyNotices: noticeRows, dependencyRedistributionReviewed: false, qualified: false, signedProvenance: false, releaseEligible: false};
  fs.writeFileSync(path.join(output, 'inventory.json'), json(report));
  fs.writeFileSync(path.join(output, 'provenance.json'), json({schema: 'kelft.alpha-provenance/1', sourceRevision: manifest.sourceRevision, sourceDirty: manifest.sourceDirty, sourceInventorySHA256: source.sourceInventorySHA256, version: release.version, target: build.target, seedManifestSHA256: build.seedManifestSHA256, artifacts, assertion: 'unsigned-local-development-evidence', releaseEligible: false}));
  fs.writeFileSync(path.join(output, 'SHA256SUMS'), artifacts.map(r => r.sha256.slice(7) + '  ' + r.file + '\n').join(''));
  return report;
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const args = options(process.argv.slice(2), ['--build', '--out', '--notices']);
  const report = await packageBuild(path.resolve(args.build), path.resolve(args.out), path.resolve(args.notices)); console.log(JSON.stringify({target: report.target, artifacts: report.artifacts, releaseEligible: false}));
}
