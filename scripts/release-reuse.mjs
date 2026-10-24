import fs from 'node:fs';
import path from 'node:path';
import {root, readJSON, json, sha256, requireThat, safeFile, safeName, newDirectory, hostTarget} from './common.mjs';
import {TARGETS, snapshot, fileIdentity, writeJSON, validateReview, validateQualification} from './release-contracts.mjs';
import {verifySeed} from './seed.mjs';
import {seedPayloadReader, copySeedInputs} from './seed-payload.mjs';
import {generation, nativePackage, extractedChecks, native, compilerCopy, languageCoverage, compilerSourceEditCheck} from './release.mjs';
import {rebuildS3} from './release-generation.mjs';

const same = (left, right, message) => requireThat(JSON.stringify(left) === JSON.stringify(right), message);
const reviewedOrchestration = /^(?:scripts\/release(?:-reuse|-contracts|-actions|-artifact)?\.mjs|tests\/release-pipeline\.test\.mjs|\.github\/workflows\/release\.yml|docs\/release-workflow\.md|publication\.json)$/;

export function retainedInputs(directory, target) {
  requireThat(TARGETS.includes(target),'Known native target required');
  if (!fs.existsSync(directory)) return null;
  const pattern = new RegExp('^(?:kit-)?' + target + '(?:-[a-f0-9]{64})?-attempt-([1-9][0-9]{0,4})$');
  const attempts = fs.readdirSync(directory).map(name => ({name, match: name.match(pattern)})).filter(row => row.match)
    .sort((a, b) => Number(b.match[1]) - Number(a.match[1]));
  for(const attempt of attempts){const from=safeFile(directory,attempt.name),report=safeFile(from,'qualification.json');if(!fs.existsSync(report))continue;const value=readJSON(report);if(value.generations?.length>=2)return from;}
  return null;
}

// Reuse measured generations only when every compiler, runtime, fixture and
// packaging input still matches. Retain the original failed or successful report.
export function validateReuseInputs(previous, inputs, current, files) {
  requireThat(previous.schema === 'kelft.release-qualification/1' && ['running','failed','passed'].includes(previous.status) && [2,3].includes(previous.generations?.length), 'Retained S2 generation required');
  const {id, ...original} = previous.snapshot;
  requireThat(sha256(json(original)) === id, 'Original snapshot identity differs');
  requireThat(inputs.schema === 'kelft.release-inputs/1' && Array.isArray(inputs.files) && inputs.files.length <= 8192, 'Retained input inventory required');
  requireThat(sha256(JSON.stringify(inputs.files)) === previous.snapshot.sourceInventorySHA256, 'Retained source inventory differs');
  requireThat(sha256(JSON.stringify(files)) === current.sourceInventorySHA256, 'Current source inventory differs');
  const component=previous.snapshot.components?.[previous.target],next=current.components?.[previous.target];
  if(component&&next){
    same(component.generation,next.generation,'Generation input changed: compiler, host, linker, runtime or mechanism');
    const seed=current.seeds[previous.target],old=previous.snapshot.seeds[previous.target];same(old.hosts,seed.hosts,'Retained host differs');same(old.compilerSHA256,seed.compilerSHA256,'Retained seed differs');
    requireThat(previous.emptyRuntimePATH===true,'Offline generation evidence required');
    const [s1,s2,s3]=previous.generations;requireThat(previous.seedManifestSHA256===old.manifestSHA256&&s1.compiler.sha256===seed.compilerSHA256,'Retained seed identity differs');requireThat(s1.name==='S1'&&s2.name==='S2'&&s2.producerCompilerSHA256===s1.compiler.sha256,'Retained producer chain differs');
    requireThat(s2.independentSourceCopy===false,'Retained S2 source required');
    if(s3){requireThat(s3.name==='S3'&&s3.producerCompilerSHA256===s2.compiler.sha256&&s3.independentSourceCopy===true,'Retained S3 source required');for(const name of ['compiler','object','policies'])same(s2[name],s3[name],'Retained generation differs');}
    for(const generation of previous.generations.slice(1)){requireThat(Object.keys(generation.policies??{}).sort().join(',')==='rebuild,testing','Retained policies missing');for(const artifact of [generation.compiler,generation.object,...Object.values(generation.policies)])requireThat(/^sha256:[a-f0-9]{64}$/.test(artifact.sha256)&&Number.isSafeInteger(artifact.bytes)&&artifact.bytes>0,'Invalid retained artifact');}
    for(const generation of previous.generations){same(generation.hosts,seed.hosts,'Retained host differs');if(generation.name!=='S1')requireThat(generation.sourceInventorySHA256===current.compilerSourcesSHA256,'Retained compiler source differs');}
    return [...new Set([...inputs.files,...files].map(row=>row.path))].filter(name=>JSON.stringify(inputs.files.find(row=>row.path===name))!==JSON.stringify(files.find(row=>row.path===name))).map(path=>({path}));
  }
  for (const field of ['version', 'compilerSourcesSHA256', 'seeds', 'seedAssetsSHA256', 'dependencyReviewSHA256', 'resourceRegistrySHA256']) {
    same(previous.snapshot[field], current[field], 'Generation input changed: ' + field);
  }
  const prior = new Map(), observed = new Map(), changes = [];
  for (const [rows, map] of [[inputs.files, prior], [files, observed]]) for (const row of rows) {
    safeName(row.path); requireThat(!map.has(row.path.toLowerCase()), 'Duplicate retained input');
    map.set(row.path.toLowerCase(), row);
  }
  for (const name of new Set([...prior.keys(), ...observed.keys()])) {
    const before = prior.get(name), after = observed.get(name);
    if (JSON.stringify(before) === JSON.stringify(after)) continue;
    requireThat(reviewedOrchestration.test(before?.path ?? after.path), 'Measured implementation or fixture changed: ' + name);
    changes.push({path: before?.path ?? after.path, before: before ?? null, after: after ?? null});
  }
  requireThat(previous.emptyRuntimePATH === true, 'Offline generation evidence required');
  const [s1, s2, s3] = previous.generations, expected = current.seeds[previous.target];
  requireThat(expected && previous.seedManifestSHA256 === expected.manifestSHA256 && s1.compiler.sha256 === expected.compilerSHA256, 'Retained seed differs');
  requireThat(s1.name==='S1'&&s2.name==='S2'&&s2.producerCompilerSHA256 === s1.compiler.sha256, 'Retained producer chain differs');
  requireThat(s2.independentSourceCopy === false, 'Retained S2 source required');
  if(s3){requireThat(s3.name==='S3'&&s3.producerCompilerSHA256===s2.compiler.sha256&&s3.independentSourceCopy===true,'Independent retained S3 required');for(const field of ['compiler','object','policies'])same(s2[field],s3[field],'Retained S2/S3 artifact differs');}
  for (const item of previous.generations) same(item.hosts, expected.hosts, 'Retained host differs');
  for (const item of previous.generations.slice(1)) requireThat(item.sourceInventorySHA256 === current.compilerSourcesSHA256, 'Retained compiler source differs');
  return changes;
}

export function reusableCoverage(coverage, minimum) {return coverage?.failed===0&&coverage.passed>=minimum&&Array.isArray(coverage.cases)&&coverage.cases.length===coverage.passed&&new Set(coverage.cases).size===coverage.passed;}

export function reuseDecision(previous,current){
 const old=previous.snapshot.components?.[previous.target],next=current.components?.[previous.target],compatible=old&&next?old.generation===next.generation:previous.snapshot.compilerSourcesSHA256===current.compilerSourcesSHA256;
 if(!compatible)return {buildGenerations:['S2','S3'],reuseLanguage:[],reuseCompilerEdit:false};
 const complete=previous.generations.length===3,testing=old&&next?old.testing===next.testing:true,compilerEdit=old&&next?old.compilerEdit===next.compilerEdit:true;
 return {buildGenerations:complete?[]:['S3'],reuseLanguage:complete&&testing?['tests','corpus'].filter((kind)=>reusableCoverage(previous.coverage?.[kind],kind==='tests'?38:53)):[],reuseCompilerEdit:complete&&compilerEdit&&previous.extracted?.compilerSourceEdit?.status==='passed'&&previous.extracted.compilerSourceEdit.actualIdentityReported===true&&previous.extracted.compilerSourceEdit.changedDiagnosticObserved===true};
}

export async function resumeQualification({directory = root, input, out, target = hostTarget(), publicCommit = null} = {}) {
  requireThat(target === hostTarget(), 'Native architecture required');
  const identity = snapshot(directory, {publicCommit}), previous = readJSON(safeFile(input, 'qualification.json'));
  requireThat(previous.target === target, 'Retained target differs');
  const inputs = readJSON(safeFile(input, 'inputs.json')), files = readJSON(path.join(directory, '.publication.json')).files;
  const changes = validateReuseInputs(previous, inputs, identity, files),decision=reuseDecision(previous,identity);
  validateReview(readJSON(path.join(directory, 'release-review.json')), directory);
  const seedDirectory = path.join(directory, 'bootstrap', target), seed = verifySeed(seedDirectory, path.join(seedDirectory, 'seed.json'), identity.seeds[target].manifestSHA256, target);
  const reader = seedPayloadReader(seedDirectory, seed), output = newDirectory(out), suffix = target.startsWith('windows-') ? '.exe' : '';
  same(fileIdentity(path.join(seedDirectory,'rootfs/compiler'+suffix)),previous.generations[0].compiler,'Retained S1 bytes differ');
  requireThat(fileIdentity(path.resolve(seedDirectory,seed.sources.file)).sha256===seed.sources.sha256,'Corresponding seed sources differ');
  const report = {schema: 'kelft.release-qualification/1', target, snapshot: identity, status: 'running',
    seedManifestSHA256: identity.seeds[target].manifestSHA256, generations: [previous.generations[0]], emptyRuntimePATH: true, releaseEligible: false,
    coverage: {}, generationReuse: {schema: 'kelft.release-generation-reuse/1', compilerGenerationsRebuilt: false, generated: [], reusedLanguageSuites: [],
      originalReportIdentity: fileIdentity(safeFile(input, 'qualification.json')), originalReport: previous,
      originalInputs: inputs, reviewedOrchestrationChanges: changes, componentInputs: identity.components?.[target]??null, rawInputs: []}};
  const save = () => writeJSON(path.join(output, 'qualification.json'), report);
  writeJSON(path.join(output, 'inputs.json'), {schema: 'kelft.release-inputs/1', files}); save();
  try {
    for (const [index, name] of previous.generations.slice(1).map(row=>row.name).entries()) {
      const destination = newDirectory(path.join(output, name)), retained = path.join(input, name);
      const retainedModes = readJSON(safeFile(retained, 'runtime-modes.json'));
      requireThat(retainedModes.schema === 'kelft.runtime-modes/1' && retainedModes.files.length <= 8192, 'Retained runtime modes required');
      const requiredPaths = new Set(retainedModes.files.map(row => safeName(row.path)));
      copySeedInputs(seedDirectory, seed, destination);
      for (const row of seed.files.filter(row => requiredPaths.has(row.path) && !/^(rootfs\/|notices\/|runtime-modes\.json$)/.test(row.path))) {
        const file = safeFile(destination, row.path);
        fs.mkdirSync(path.dirname(file), {recursive: true});
        fs.writeFileSync(file, reader.read(row.path), {flag: 'wx', mode: row.mode});
      }
      for (const name of ['rebuild.json', 'runtime-modes.json', ...(fs.existsSync(safeFile(retained,'release.json'))?['release.json']:[]), 'compiler' + (suffix ? '.obj' : '.o'), 'rootfs/compiler' + suffix,
        'rootfs/policies/rebuild' + suffix, 'rootfs/policies/testing' + suffix]) {
        const source = safeFile(retained, name), file = safeFile(destination, name);
        fs.mkdirSync(path.dirname(file), {recursive: true});
        if (fs.existsSync(file)) fs.chmodSync(file, 0o644);
        fs.copyFileSync(source, file);
        report.generationReuse.rawInputs.push({path: path.posix.join(index === 0 ? 'S2' : 'S3', name), ...fileIdentity(source)});
      }
      const receipt = readJSON(path.join(destination, 'rebuild.json'));
      requireThat(sha256(JSON.stringify(receipt.sources)) === identity.compilerSourcesSHA256, 'Retained receipt source inventory differs');
      const modes = readJSON(path.join(destination, 'runtime-modes.json'));
      requireThat(modes.schema === 'kelft.runtime-modes/1' && modes.files.length <= 8192, 'Retained runtime modes required');
      for (const row of modes.files) {requireThat([0o444, 0o555, 0o600, 0o644, 0o700, 0o755].includes(row.mode), 'Retained mode differs'); const file = safeFile(destination, row.path); requireThat(fs.existsSync(file), 'Retained runtime file missing: '+row.path); if (process.platform !== 'win32') fs.chmodSync(file, row.mode);}
      const measured = generation(destination, index === 0 ? 'S2' : 'S3', index === 1);
      same(measured, previous.generations[index + 1], 'Retained generation bytes differ');
      report.generations.push(measured); save();
    }
    const logs=path.join(output,'logs');
    if(decision.buildGenerations.includes('S3')){const source=path.join(output,'independent source');compilerCopy(directory,source);rebuildS3(path.join(output,'S2'),source,path.join(output,'S3'),directory,logs);report.generations.push(generation(path.join(output,'S3'),'S3',true));report.generationReuse.compilerGenerationsRebuilt=true;report.generationReuse.generated.push('S3');save();}
    for(const field of ['compiler','object','policies'])same(report.generations[1][field],report.generations[2][field],'Continued S2/S3 '+field+' differs');
    const cli=path.join(output,'S3/bin/kelft'+suffix),missing=[];
    for(const [kind,minimum]of [['tests',38],['corpus',53]]){if(decision.reuseLanguage.includes(kind)){report.coverage[kind]=previous.coverage[kind];report.generationReuse.reusedLanguageSuites.push(kind);}else missing.push(kind);}
    if(missing.length){const project=path.join(output,'language project');compilerCopy(directory,project,{tests:true});const completed={...report.coverage};languageCoverage(cli,project,logs,missing,partial=>{report.coverage={...completed,...partial};save();});}save();
    const name = 'kelft-v' + identity.version + '-' + target + (suffix ? '.zip' : '.tar.gz');
    if(previous.reproduciblePackage===true&&previous.generations.length===3&&(!identity.components||previous.snapshot.components?.[target]?.packaging===identity.components[target].packaging)){const original=fileIdentity(safeFile(input,name));for (const generation of ['S2', 'S3']) {
      const old = nativePackage(path.join(output, generation), path.join(output, 'original-' + generation + '-' + name), previous.snapshot, target, directory);
      same({bytes: old.bytes, sha256: old.sha256}, original, 'Retained package reconstruction differs');
    }}
    const first = nativePackage(path.join(output, 'S2'), path.join(output, 'S2-' + name), identity, target, directory);
    const second = nativePackage(path.join(output, 'S3'), path.join(output, name), identity, target, directory);
    same({bytes: first.bytes, sha256: first.sha256}, {bytes: second.bytes, sha256: second.sha256}, 'Continued packages differ');
    report.reproduciblePackage = true;
    report.artifact = {file: name, bytes: second.bytes, sha256: second.sha256};
    writeJSON(path.join(output, 'inventory.json'), {schema: 'kelft.native-release-inventory/1', target, snapshotID: identity.id, files: second.files}); save();
    report.extracted = await extractedChecks(path.join(output, name), second, output, directory);
    if (target === 'windows-x86_64') report.extracted.compilerSourceEdit = decision.reuseCompilerEdit?previous.extracted.compilerSourceEdit:compilerSourceEditCheck(cli,directory,output,logs);
    same(snapshot(directory, {publicCommit}), identity, 'Sources changed during continuation');
    report.status = 'passed'; validateQualification(report, identity); save(); return report;
  } catch (error) {report.status = 'failed'; report.error = String(error); save(); throw error;}
}
