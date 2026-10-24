import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {Readable, Transform} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import {inventory, sha256, requireThat, newDirectory, safeName} from './common.mjs';
import {TARGETS, fileIdentity} from './release-contracts.mjs';

function proofReader(){return process.platform==='linux'?'/usr/bin/unzip':process.platform==='win32'?path.join(process.env.SystemRoot,'System32/tar.exe'):'/usr/bin/tar';}
export function readProofMember(archive,name){safeName(name);requireThat(!name.startsWith('-'),'Proof option-like path rejected');const resolved=path.resolve(archive),args=process.platform==='linux'?['-p',path.basename(resolved),name]:['-xOf',path.basename(resolved),'--',name];return execFileSync(proofReader(),args,{cwd:path.dirname(resolved),windowsHide:true,maxBuffer:256*1024*1024});}
export function authenticateProofDirectory(archive, expectedSHA256, directory) {
  requireThat(/^sha256:[a-f0-9]{64}$/.test(expectedSHA256), 'Artifact SHA-256 required');
  requireThat(fileIdentity(archive).sha256 === expectedSHA256, 'Artifact ZIP differs');
  const tar = proofReader();
  const extractor = fileIdentity(tar), rows = inventory(directory);
  requireThat(rows.length > 0 && rows.reduce((sum, row) => sum + row.bytes, 0) <= 512 * 1024 * 1024, 'Proof input bound');
  for (const row of rows) {
    const bytes = readProofMember(archive,row.path);
    requireThat(bytes.length === row.bytes && sha256(bytes) === row.sha256, 'Extracted proof member differs: ' + row.path);
  }
  requireThat(fileIdentity(archive).sha256 === expectedSHA256 && fileIdentity(tar).sha256 === extractor.sha256, 'Proof transport changed');
  return {archive: fileIdentity(archive), extractor, files: rows.length};
}

export async function authenticateRemoteArtifact({directory, target, runID, artifactID = null, token, repository, workflow, branch, expectedCommit = null, completed = false, fetcher = fetch, kitKey = null, materialize = false, seedRefresh = false}) {
  requireThat(TARGETS.includes(target), 'Known proof target required');
  requireThat(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? '') && /^\.github\/workflows\/[A-Za-z0-9_.-]+\.yml$/.test(workflow ?? ''), 'Proof repository and workflow required');
  requireThat(token && Number.isSafeInteger(runID) && runID > 0, 'Authenticated proof identity required');
  const headers = {Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'};
  const endpoint = 'https://api.github.com/repos/' + repository;
  async function get(suffix) {const response = await fetcher(endpoint + suffix, {headers}); requireThat(response.ok, 'Proof metadata fetch failed: ' + response.status); return response.json();}
  if(artifactID===null){for(let page=1;page<=10;page++){const listing=await get('/actions/runs/'+runID+'/artifacts?per_page=100&page='+page);requireThat(Array.isArray(listing.artifacts)&&listing.artifacts.length<=100,'Proof artifact listing differs');const match=listing.artifacts.find(row=>row.name===path.basename(directory));if(match){artifactID=match.id;break;}if(listing.artifacts.length<100)break;}}
  requireThat(Number.isSafeInteger(artifactID)&&artifactID>0,'Retained artifact identity required');
  const [run, artifact] = await Promise.all([get('/actions/runs/' + runID), get('/actions/artifacts/' + artifactID)]);
  requireThat((completed ? run.status === 'completed' : ['completed','in_progress'].includes(run.status)) && run.head_branch === branch && run.path === workflow && run.head_repository?.full_name === repository, 'Unexpected proof producer');
  if(seedRefresh)requireThat(run.event==='workflow_dispatch'&&repository==='kelftlang/kelft'&&['dev','main'].includes(branch),'Seed refresh requires a manual public producer');
  requireThat(expectedCommit === null || run.head_sha === expectedCommit, 'Proof workflow revision differs');
  const prefix = workflow === '.github/workflows/release.yml' ? '' : 'qualification-';
  requireThat(artifact.workflow_run?.id === runID && artifact.workflow_run.head_sha === run.head_sha && (seedRefresh?new RegExp('^seed-refresh-'+target+'-attempt-[1-9][0-9]*$'):kitKey?new RegExp('^(?:kit-'+target+'-'+kitKey+'|'+prefix+target+')-attempt-[1-9][0-9]*$'):new RegExp('^'+prefix+target+'-attempt-[1-9][0-9]*$')).test(artifact.name),'Artifact producer or target differs');
  requireThat(/^sha256:[a-f0-9]{64}$/.test(artifact.digest ?? '') && artifact.size_in_bytes > 0 && artifact.size_in_bytes <= 512 * 1024 * 1024, 'Artifact digest or size missing');
  requireThat(!artifact.expired,'Kit artifact expired');if(kitKey)requireThat(/^[a-f0-9]{64}$/.test(kitKey),'Invalid generation key');
  const transport = newDirectory(path.join(path.dirname(path.resolve(directory)), 'proof-transport-' + artifactID)), archive = path.join(transport, 'proof.zip');
  const response = await fetcher(endpoint + '/actions/artifacts/' + artifactID + '/zip', {headers});
  requireThat(response.ok, 'Proof ZIP download failed: HTTP ' + response.status);
  let bytes = 0;
  const bound = new Transform({transform(chunk, encoding, done) {bytes += chunk.length; done(bytes > artifact.size_in_bytes ? Error('Proof ZIP size exceeded') : null, chunk);}});
  await pipeline(Readable.fromWeb(response.body), bound, fs.createWriteStream(archive, {flags: 'wx'}));
  requireThat(bytes === artifact.size_in_bytes, 'Proof ZIP truncated');
  requireThat(fileIdentity(archive).sha256===artifact.digest,'Artifact ZIP differs');
  if(materialize){
    requireThat(!fs.lstatSync(directory).isSymbolicLink()&&fs.readdirSync(directory).length===0,'Kit materialization requires an empty regular directory');
    const reader=proofReader(),names=execFileSync(reader,process.platform==='linux'?['-Z','-1',path.basename(archive)]:['-tf',path.basename(archive)],{cwd:path.dirname(archive),encoding:'utf8',maxBuffer:1<<20,windowsHide:true}).trim().split(/\r?\n/).filter(name=>!name.endsWith('/'));requireThat(names.length>0&&names.length<=8192&&new Set(names.map(name=>name.toLowerCase())).size===names.length,'Invalid kit member set');let total=0;
    for(const name of names){safeName(name);const bytes=readProofMember(archive,name);total+=bytes.length;requireThat(total<=512*1024*1024,'Kit extraction exceeds bound');const file=path.join(directory,name);fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,bytes,{flag:'wx'});}
  }
  const verified = authenticateProofDirectory(archive, artifact.digest, directory);
  return {repository, workflow: run.path, run: runID, artifact: artifactID, commit: run.head_sha, branch: run.head_branch, ...verified};
}
