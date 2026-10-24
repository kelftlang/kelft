import fs from 'node:fs';import path from 'node:path';
import {readJSON,json,sha256,requireThat,safeName,safeFile} from './common.mjs';
export function inputClosure(directory,entry,files){
 const available=new Map(files.map(row=>[row.path,row])),seen=new Set(),pending=[safeName(entry)];
 while(pending.length){const name=pending.pop();if(seen.has(name))continue;requireThat(/^(selfhost|stdlib)\/.+\.kelft$/.test(name),'Compiler import outside source roots');const row=available.get(name);requireThat(row,'Missing component input: '+name);const bytes=fs.readFileSync(safeFile(directory,name));requireThat(sha256(bytes)===row.sha256&&bytes.length===row.bytes,'Component input changed: '+name);seen.add(name);for(const match of bytes.toString('utf8').matchAll(/^\s*import\s+"([^"\r\n]+)"/gm)){const imported=path.posix.normalize(path.posix.join(path.posix.dirname(name),match[1]));safeName(imported);pending.push(imported);}}
 return [...seen].sort().map(name=>{const {path,bytes,sha256}=available.get(name);return {path,bytes,sha256};});
}
export function executionInputs(files,target){return selected(files,name=>name.startsWith('bootstrap/'+target+'/')&&(name.includes('/rootfs/')||name.includes('/parts/')||name.endsWith('/bin/kelft-boundary')||name.endsWith('/bin/kelft-boundary.exe'))&&!/\/rootfs\/(?:source|policies)\//.test(name));}
const hash=value=>sha256(json(value));
const selected=(files,predicate)=>files.filter(row=>predicate(row.path)).map(({path,bytes,sha256})=>({path,bytes,sha256})).sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
export function componentIdentities({files,target,entry,seed,assets,baseline,resourceProfile}){
  requireThat(/^(?:linux|windows|macos)-(?:x86_64|arm64)$/.test(target),'Known identity target required');const seen=new Set();
  for(const row of files){safeName(row.path);requireThat(!seen.has(row.path.toLowerCase())&&/^sha256:[a-f0-9]{64}$/.test(row.sha256)&&Number.isSafeInteger(row.bytes)&&row.bytes>=0,'Invalid component input');seen.add(row.path.toLowerCase());}
  const compiler=selected(files,name=>/^(selfhost|stdlib)\/.+\.kelft$/.test(name));requireThat(compiler.some(row=>row.path===entry),'Compiler entry missing from inputs');
  const runtime=assets.files.filter(row=>row.path.startsWith(target+'/')&&!/^(?:notices|provenance)(?:\/|$)/.test(row.path.slice(target.length+1))&&!['seed.json','runtime-modes.json','READY','release.json','host-features.json'].includes(row.path.slice(target.length+1))).map(({path,sha256,bytes,mode})=>({path,sha256,bytes,mode})).sort((a,b)=>a.path<b.path?-1:1);
  requireThat(runtime.length>0,'Selected native runtime inputs required');
  const generationMechanisms=selected(files,name=>['scripts/release-generation.mjs','scripts/common.mjs'].includes(name));requireThat(generationMechanisms.length===2,'Generation mechanisms missing');
  const generation=hash({schema:'kelft.generation-inputs/1',target,entry,baseline,resourceProfile,compiler,producer:{compiler:seed.producer.compilerSHA256,coordinator:seed.producer.coordinatorSHA256,boundary:seed.producer.boundarySHA256},runtime,mechanisms:generationMechanisms});
  const testing=hash({schema:'kelft.test-inputs/1',generation,files:selected(files,name=>/^tests\/(?:kelft\/|fixtures\/|conformance\.json$|native-conformance\.json$)/.test(name)||name==='scripts/release-language.mjs')});
  const packaging=hash({schema:'kelft.package-inputs/1',generation,files:selected(files,name=>/^(?:release\.json|INSTALL\.md|LICENSE.*|TRADEMARKS\.md|licensing\.json)$/.test(name)||name.startsWith('LICENSES/')||['scripts/release-package.mjs','scripts/archive.mjs'].includes(name)),notices:assets.files.filter(row=>row.path.startsWith(target+'/notices/'))});
  const controls=hash({schema:'kelft.package-controls/1',testing,packaging,files:selected(files,name=>name==='scripts/release-checks.mjs'||name.startsWith('examples/'))});
  const compilerEdit=hash({generation,files:selected(files,name=>name==='scripts/release-language.mjs')});
  return {schema:'kelft.release-components/1',generation,testing,packaging,controls,compilerEdit};
}
export function releaseComponents(directory,files,release,assets){return Object.fromEntries(Object.entries(release.targets).map(([target,profile])=>{
 const seed=readJSON(path.join(directory,'bootstrap',target,'seed.json')),resourceProfile=readJSON(path.join(directory,'host/native/resource-contracts.json')).profiles[target],legacy=componentIdentities({files,target,entry:profile.entry,baseline:profile.baseline,resourceProfile,seed,assets});
 const coreSources=inputClosure(directory,profile.entry,files),policies=Object.fromEntries(['rebuild','testing'].map(name=>[name,hash(inputClosure(directory,'selfhost/toolchain/'+name+'.kelft',files))])),runtime=executionInputs(files,target);
 return [target,{...legacy,core:hash({target,profile,coreSources,runtime,resourceProfile,producerCompiler:seed.producer.compilerSHA256}),coreSources,policies,language:hash(selected(files,name=>/^tests\/(?:kelft\/|fixtures\/|conformance\.json$|native-conformance\.json$)/.test(name))),host:hash(selected(files,name=>name==='scripts/seed-host.mjs'||/^host\/(?:driver\/|scripts\/|native\/)/.test(name)&&name!=='host/driver/release.json'))}];
}));}
