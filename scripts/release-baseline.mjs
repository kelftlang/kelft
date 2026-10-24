// Retained compiler evidence keeps its original producers and source snapshot.
import fs from 'node:fs';import path from 'node:path';
import {readJSON,json,sha256,requireThat,safeFile,newDirectory} from './common.mjs';
import {fileIdentity,validateQualification,TARGETS} from './release-contracts.mjs';
import {inputClosure,executionInputs} from './release-identities.mjs';
import {authenticateRemoteArtifact} from './release-artifact.mjs';
import {githubSignature} from './release-source.mjs';
export const BASELINE=Object.freeze({repository:'kelftlang/kelft',workflow:'.github/workflows/release.yml',branch:'main',runID:40059868983,commit:'64b4da174db450ff96a9ce7a04555d3514758fe9',snapshot:'sha256:958416883845807639591515188cb6220f9718682d45bde6bc119d7218b69780'});
const same=(a,b,message)=>requireThat(JSON.stringify(a)===JSON.stringify(b),message);
export async function baselineMetadata({token,fetcher=fetch}){
 const get=async route=>{const response=await fetcher('https://api.github.com/repos/'+BASELINE.repository+route,{headers:{Authorization:'Bearer '+token,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}});requireThat(response.ok,'Retained compiler metadata unavailable: '+response.status);return response.json();};
 githubSignature(await get('/commits/'+BASELINE.commit),BASELINE.commit);
 const read=async name=>{const row=await get('/contents/'+name+'?ref='+BASELINE.commit);requireThat(row.encoding==='base64'&&typeof row.content==='string'&&row.content.length<6<<20,'Invalid retained source metadata');const bytes=Buffer.from(row.content,'base64');requireThat(bytes.length<=4<<20,'Retained source metadata bound');return {value:JSON.parse(bytes),sha256:sha256(bytes)};};
 const publication=await read('.publication.json'),release=await read('release.json');requireThat(publication.value.files.find(row=>row.path==='release.json')?.sha256===release.sha256,'Retained release identity differs');return {files:publication.value.files,release:release.value};
}
export async function loadBaseline({directory,target,out,token,fetcher=fetch}){
 requireThat(TARGETS.includes(target),'Known retained target required');const metadata=await baselineMetadata({token,fetcher}),input=newDirectory(out);
 const listing=await fetcher('https://api.github.com/repos/'+BASELINE.repository+'/actions/runs/'+BASELINE.runID+'/artifacts?per_page=100',{headers:{Authorization:'Bearer '+token,Accept:'application/vnd.github+json'}});requireThat(listing.ok,'Retained artifacts unavailable');const artifacts=(await listing.json()).artifacts;requireThat(Array.isArray(artifacts)&&artifacts.length<100,'Retained artifact listing bound');const matches=artifacts.filter(row=>new RegExp('^'+target+'-attempt-[1-9][0-9]*$').test(row.name)&&!row.expired);requireThat(matches.length===1,'Missing or ambiguous retained compiler artifact; no replacement builds were started');
 const transport=await authenticateRemoteArtifact({directory:input,target,...BASELINE,artifactID:matches[0].id,expectedCommit:BASELINE.commit,completed:true,token,fetcher,materialize:true});
 const report=readJSON(safeFile(input,'qualification.json'));requireThat(report.snapshot.id===BASELINE.snapshot&&report.snapshot.publicCommit===BASELINE.commit&&report.target===target,'Unexpected retained compiler snapshot');validateQualification(report,report.snapshot);
 requireThat(sha256(JSON.stringify(metadata.files))===report.snapshot.sourceInventorySHA256,'Retained publication inventory differs');
 for(const generation of report.generations.slice(1)){const suffix=target.startsWith('windows')?'.exe':'';for(const [name,identity]of [['rootfs/compiler'+suffix,generation.compiler],['compiler'+(suffix?'.obj':'.o'),generation.object],...Object.entries(generation.policies).map(([name,row])=>['rootfs/policies/'+name+suffix,row])])same(fileIdentity(safeFile(input,generation.name+'/'+name)),identity,'Retained output differs: '+name);}
 return {report,files:metadata.files,release:metadata.release,transport,input};
}
export function adoptCompiler({directory,target,report,files,release}){
 requireThat(TARGETS.includes(target)&&report.target===target&&report.snapshot.id===BASELINE.snapshot&&report.snapshot.publicCommit===BASELINE.commit,'Unexpected retained compiler evidence');validateQualification(report,report.snapshot);
 requireThat(sha256(JSON.stringify(files))===report.snapshot.sourceInventorySHA256,'Retained input inventory differs');
 const currentFiles=readJSON(path.join(directory,'.publication.json')).files,currentRelease=readJSON(path.join(directory,'release.json')),old=new Map(files.map(row=>[row.path,row]));
 same(release.targets[target],currentRelease.targets[target],'Compiler target contract changed');for(const key of ['coreVersion','intentVersion'])same(release[key],currentRelease[key],'Compiler language contract changed');
 const closure=inputClosure(directory,currentRelease.targets[target].entry,currentFiles);for(const row of closure){const prior=old.get(row.path);requireThat(prior?.sha256===row.sha256&&prior.bytes===row.bytes,'Compiler source changed: '+row.path);}
 for(const row of inputClosure(directory,'selfhost/toolchain/testing.kelft',currentFiles)){const prior=old.get(row.path);requireThat(prior?.sha256===row.sha256&&prior.bytes===row.bytes,'Testing policy source changed; targeted policy qualification required: '+row.path);}
 for(const row of executionInputs(currentFiles,target)){const prior=old.get(row.path);requireThat(prior?.sha256===row.sha256&&prior.bytes===row.bytes,'Compiler execution input changed: '+row.path);}
 const suffix=target.startsWith('windows')?'.exe':'',seed=readJSON(path.join(directory,'bootstrap',target,'seed.json')),compiler=seed.files.find(row=>row.path==='rootfs/compiler'+suffix),testing=seed.files.find(row=>row.path==='rootfs/policies/testing'+suffix);
 requireThat(compiler?.sha256===report.generations[2].compiler.sha256&&compiler.sha256===seed.producer.compilerSHA256,'Retained compiler image changed');requireThat(testing?.sha256===report.generations[2].policies.testing.sha256,'Testing policy image changed');
 const languageRows=rows=>rows.filter(row=>/^tests\/(?:kelft\/|fixtures\/|conformance\.json$|native-conformance\.json$)/.test(row.path));
 const languageReusable=JSON.stringify(languageRows(files))===JSON.stringify(languageRows(currentFiles));
 return {schema:'kelft.compiler-adoption/1',target,compiler:report.generations[2].compiler,object:report.generations[2].object,coreSources:closure,executionInputs:executionInputs(currentFiles,target),languageReusable,originalSnapshotID:report.snapshot.id,originalReportSHA256:sha256(json(report)),producerCommit:BASELINE.commit,compilerGenerationsRebuilt:false};
}
