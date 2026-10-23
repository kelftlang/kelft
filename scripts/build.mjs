import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {root, readJSON, json, requireThat, sha256, inventory, verifyInventory, hostTarget, run, compilerEnvironment, newDirectory, options} from './common.mjs';
import {verifySeed} from './seed.mjs';
import {copySeedInputs} from './seed-payload.mjs';
import {checkSource, sourceInventory} from './check.mjs';

function compilerInputs(manifest, target, entry, maximum) {
  return sha256(JSON.stringify({target, entry, maximum, files: manifest.files.filter(r => /^(selfhost|stdlib)\//.test(r.path))}));
}
export async function build({seed: seedDirectory, manifest: seedManifest, sha256: expected, sources, out, phase = 'installed', toolchain, 'reuse-compiler': previousDirectory}, directory = root) {
  requireThat(['compiler', 'installed'].includes(phase), 'Unknown build phase');
  const before = checkSource(directory), release = readJSON(path.join(directory, 'release.json')), target = hostTarget(), profile = release.targets[target];
  requireThat(path.resolve(out).startsWith(path.join(directory, 'build') + path.sep), 'Build output must be below the public source build/ directory');
  const seed = verifySeed(seedDirectory, seedManifest, expected, target);
  requireThat(sources && sha256(fs.readFileSync(sources)) === seed.sources.sha256, 'Supply the matching seed source archive');
  const output = newDirectory(out), windows = target.startsWith('windows-'), mac = target.startsWith('macos-'), suffix = windows ? '.exe' : '';
  const packageRoot = path.join(output, 'package'); fs.mkdirSync(packageRoot);
  copySeedInputs(seedDirectory,seed,packageRoot);
  // Seed authentication precedes copying. Optional components are never enabled
  // in newly built hosts; the native linker/SDK closure is retained verbatim.
  for (const name of ['rootfs/engines', 'rootfs/cross', 'rootfs/compiler.obj', 'rootfs/compiler.o', 'rootfs/control/engine-profiles.json', 'rootfs/control/cross-linux-x86_64.json']) {
    const file = path.join(packageRoot, name); if (fs.existsSync(file)) fs.rmSync(file, {recursive: true});
  }
  fs.mkdirSync(path.join(packageRoot, 'bin'));
  const compiler = path.join(packageRoot, 'rootfs/compiler' + suffix), object = path.join(packageRoot, 'rootfs/compiler' + (windows ? '.obj' : '.o')), maximum = path.join(output, 'maximum.json');
  if(fs.existsSync(compiler))fs.unlinkSync(compiler);
  fs.writeFileSync(maximum, json(seed.maximum));
  const report = {schema: 'kelft.public-build/1', status: 'building', target, version: release.version, sourceInventorySHA256: before.sourceInventorySHA256, sourceDirty: before.sourceDirty, seedManifestSHA256: expected, seedProducer: seed.producer, phase, compilerGenerationsRebuilt: false, certified: false, releaseEligible: false};
  const sourceManifest = readJSON(path.join(directory, '.publication.json'));
  sourceManifest.files = sourceInventory(directory);
  fs.writeFileSync(path.join(output, 'source-inventory.json'), json(sourceManifest));
  let previous = null;
  const save = () => fs.writeFileSync(path.join(output, 'build.json'), json(report)); save();
  try {
    if (previousDirectory) {
      const priorBytes = fs.readFileSync(path.join(previousDirectory, 'build.json')), prior = JSON.parse(priorBytes), priorSources = readJSON(path.join(previousDirectory, 'source-inventory.json'));
      requireThat(prior.target === target && prior.seedManifestSHA256 === expected && prior.compiler && prior.object, 'Previous compiler has incompatible inputs');
      requireThat(sha256(JSON.stringify(priorSources.files)) === prior.sourceInventorySHA256, 'Previous source inventory changed');
      requireThat(compilerInputs(priorSources, target, profile.entry, readJSON(path.join(previousDirectory, 'maximum.json'))) === compilerInputs(sourceManifest, target, profile.entry, seed.maximum), 'Compiler source or maximum changed');
      const priorCompiler = path.join(previousDirectory, 'package/rootfs/compiler' + suffix), priorObject = path.join(previousDirectory, path.basename(object));
      requireThat(sha256(fs.readFileSync(priorCompiler)) === prior.compiler.sha256 && sha256(fs.readFileSync(priorObject)) === prior.object.sha256, 'Previous compiler output changed');
      fs.copyFileSync(priorCompiler, compiler); fs.copyFileSync(priorObject, path.join(output, path.basename(object)));
      report.compiler = prior.compiler; report.object = prior.object; report.reusedCompiler = {buildSHA256: sha256(priorBytes), sourceInventorySHA256: prior.sourceInventorySHA256};
      previous = {report: prior, sources: priorSources};
    } else {
      const result = run(path.join(seedDirectory, 'bin/kelft' + suffix), ['native-build', profile.entry, '--project-root', directory, '--capabilities', maximum, '--object-output', object, '-o', compiler], {cwd: directory, env: compilerEnvironment()});
      fs.writeFileSync(path.join(output, 'compiler.log'), result.stdout + result.stderr);
      report.compiler = {sha256: sha256(fs.readFileSync(compiler)), bytes: fs.statSync(compiler).size};
      report.object = {sha256: sha256(fs.readFileSync(object)), bytes: fs.statSync(object).size};
      fs.renameSync(object, path.join(output, path.basename(object)));
      requireThat(JSON.parse(result.stdout).executableHash === report.compiler.sha256, 'Compiler build receipt differs');
    }
    if(process.platform!=='win32')fs.chmodSync(compiler,0o755);
    save();
    if (phase === 'installed') {
      const testingPolicy = path.join(output, 'testing-policy' + suffix), testingMaximum = path.join(output, 'testing-maximum.json');
      fs.writeFileSync(testingMaximum, json({read: ['/project'], write: [], execute: false}));
      if (previous?.report.testingPolicySHA256 && JSON.stringify(readJSON(path.join(previousDirectory, 'testing-maximum.json'))) === JSON.stringify(readJSON(testingMaximum))) {
        const prepared = path.join(previousDirectory, path.basename(testingPolicy));
        requireThat(sha256(fs.readFileSync(prepared)) === previous.report.testingPolicySHA256, 'Previous testing policy changed'); fs.copyFileSync(prepared, testingPolicy);
      } else run(path.join(seedDirectory, 'bin/kelft' + suffix), ['native-build', 'selfhost/toolchain/testing.kelft', '--project-root', directory, '--capabilities', testingMaximum, '-o', testingPolicy], {cwd: directory, env: compilerEnvironment()});
      report.testingPolicySHA256 = sha256(fs.readFileSync(testingPolicy));
      const rebuildPolicy = path.join(output, 'rebuild-policy' + suffix);
      run(path.join(seedDirectory, 'bin/kelft' + suffix), ['native-build', 'selfhost/toolchain/rebuild.kelft', '--project-root', directory, '--capabilities', testingMaximum, '-o', rebuildPolicy], {cwd: directory, env: compilerEnvironment()});
      report.rebuildPolicySHA256 = sha256(fs.readFileSync(rebuildPolicy));
      const policyDirectory = path.join(packageRoot,'rootfs/policies');fs.mkdirSync(policyDirectory,{recursive:true});
      fs.copyFileSync(testingPolicy,path.join(policyDirectory,'testing'+suffix));fs.copyFileSync(rebuildPolicy,path.join(policyDirectory,'rebuild'+suffix));
      const hostRun = (file, args, name, settings = {}) => {
        const result = run(file, args, {cwd: path.join(directory, 'host'), ...settings});
        fs.writeFileSync(path.join(output, name + '.log'), result.stdout + result.stderr); return result;
      };
      const configuration = path.join(packageRoot, 'rootfs/control/toolchain.json');
      const hostFiles = manifest => manifest.files.filter(row => row.path.startsWith('host/'));
      if (previous?.report.status === 'built' && previous.report.host && report.rebuildPolicySHA256 === previous.report.rebuildPolicySHA256 && report.testingPolicySHA256 === previous.report.testingPolicySHA256 && JSON.stringify(hostFiles(previous.sources)) === JSON.stringify(hostFiles(sourceManifest))) {
        verifyInventory(path.join(previousDirectory, 'package'), previous.report.installedFiles);
        fs.cpSync(path.join(previousDirectory, 'package'), packageRoot, {recursive: true});
        verifyInventory(packageRoot, previous.report.installedFiles);
        report.host = previous.report.host; report.reusedHost = {buildSHA256: report.reusedCompiler.buildSHA256, originalSourceInventorySHA256: previous.report.sourceInventorySHA256};
      } else if (windows) {
        const {buildWindowsInstalledHost} = await import('../host/scripts/build-native-windows-installed-host.mjs');
        report.host = buildWindowsInstalledHost({directory: path.join(output, 'host'), packageRoot, compiler, configuration, run: hostRun, testingPolicy, rebuildPolicy});
      } else if (mac) {
        requireThat(toolchain, 'Supply the prepared macOS toolchain configuration');
        const config = readJSON(toolchain), {inventoryNativeToolchain} = await import('../host/scripts/direct-toolchain.mjs');
        report.toolchain = inventoryNativeToolchain(config);
        const {buildMacosInstalledHost} = await import('../host/scripts/build-native-macos-installed-host.mjs');
        report.host = buildMacosInstalledHost({directory: path.join(output, 'host'), packageRoot, compiler, configuration: path.join(packageRoot, 'rootfs/control/linker.json'), session: configuration, toolchain: config, run: hostRun, testingPolicy, rebuildPolicy});
      } else {
        // Recreate the existing Linux bundle contract with the newly built
        // compiler, then use its unchanged supervisor and host builders.
        const bundle = path.join(output, 'bundle'); fs.renameSync(packageRoot, bundle);
        const rootfs = path.join(bundle, 'rootfs'); fs.writeFileSync(path.join(rootfs, 'control/maximum.json'), json(seed.maximum));
        for (const name of ['selfhost', 'stdlib']) fs.cpSync(path.join(directory, name), path.join(rootfs, 'source', name), {recursive: true});
        const {hash} = await import('../host/scripts/ai/common.mjs');
        const config = readJSON(path.join(rootfs, 'control/toolchain.json'));
        fs.writeFileSync(path.join(bundle, 'manifest.json'), json({schema: 'kelft-native-standalone-bundle/1', profile: target, compilerHash: report.compiler.sha256, maximumHash: sha256(json(seed.maximum)), configurationIdentity: config.identity, files: Object.fromEntries(inventory(rootfs).map(r => [r.path, {sha256: r.sha256, size: r.bytes, mode: r.mode}])), productionClosureVerified: false, releaseEligible: false}));
        requireThat(hash(fs.readFileSync(path.join(rootfs, 'control/maximum.json'))) === sha256(json(seed.maximum)), 'Maximum identity differs');
        const {stageInstalledSupervisor} = await import('../host/scripts/stage-native-installed.mjs');
        const host = stageInstalledSupervisor({bundle, directory: path.join(output, 'host'), nativeCoordinator: true, buildRoot: output, testingPolicy, rebuildPolicy});
        fs.renameSync(host.destination, packageRoot); report.host = host;
        if(fs.existsSync(path.join(bundle,'notices')))fs.cpSync(path.join(bundle,'notices'),path.join(packageRoot,'notices'),{recursive:true});
      }
      const modeRows=inventory(packageRoot).filter(row=>row.path!=='runtime-modes.json').map(row=>({path:row.path,mode:windows?(row.path.startsWith('bin/')||row.path.endsWith('.exe')?0o755:0o644):row.mode}));
      requireThat(modeRows.every(row=>[0o444,0o555,0o600,0o644,0o700,0o755].includes(row.mode)),'Host build outputs require native filesystem permissions');
      fs.writeFileSync(path.join(packageRoot,'runtime-modes.json'),json({schema:'kelft.runtime-modes/1',files:modeRows}));
      const cli = path.join(packageRoot, 'bin/kelft' + suffix), env = compilerEnvironment();
      const version = run(cli, ['version'], {env}).stdout;
      requireThat(version.startsWith('kelft ' + release.version + ';'), 'Public version mismatch');
      requireThat(JSON.parse(run(cli, ['doctor', '--json'], {env}).stdout).status === 'success', 'Installed identities failed');
      report.versionOutput = version.trim();
    }
    requireThat(checkSource(directory).sourceInventorySHA256 === before.sourceInventorySHA256, 'Source changed during build');
    verifySeed(seedDirectory, seedManifest, expected, target);
    report.installedFiles = phase === 'installed' ? inventory(packageRoot) : null;
    report.status = 'built'; save(); return report;
  } catch (error) { report.status = 'failed'; report.error = error.message; save(); throw error; }
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const args = options(process.argv.slice(2), ['--seed', '--manifest', '--sha256', '--sources', '--out', '--phase', '--toolchain', '--reuse-compiler']);
  for (const name of ['seed', 'manifest', 'out']) { requireThat(args[name], 'Missing --' + name); args[name] = path.resolve(args[name]); }
  const report = await build(args); console.log(JSON.stringify({status: report.status, target: report.target, compiler: report.compiler, object: report.object, releaseEligible: false}));
}
