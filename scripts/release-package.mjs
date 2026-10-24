import {tarGzip,zip} from './archive.mjs';
import {hosts} from './release-generation.mjs';
import fs from 'node:fs';import path from 'node:path';import {spawn,spawnSync,execFileSync} from 'node:child_process';
import {root,readJSON,json,sha256,requireThat,inventory,safeFile,newDirectory,hostTarget,compilerEnvironment} from './common.mjs';import {fileIdentity,writeJSON} from './release-contracts.mjs';
const same=(a,b,message)=>requireThat(JSON.stringify(a)===JSON.stringify(b),message),suffix=()=>process.platform==='win32'?'.exe':'';
export function nativePackage(installation,output,identity,target,directory=root,components=null){
  const files=inventory(installation),recorded=readJSON(path.join(installation,'runtime-modes.json')),modes=new Map(recorded.files.map(row=>[row.path,row.mode])),rows=[];
  const omitted=name=>['release.json','rebuild.json','compiler.o','compiler.obj','seed.json','READY','.protocol-checked.json','runtime-modes.json'].includes(name);
  for(const row of files){if(omitted(row.path))continue;requireThat(!/(^|\/)(engines|cross|\.kelft-targets)(\/|$)|engine-profiles/.test(row.path),'Optional engine in native release');const mode=modes.get(row.path)??(target.startsWith('windows')?(row.path.endsWith('.exe')?0o755:0o644):row.mode);rows.push({path:row.path,file:safeFile(installation,row.path),sha256:row.sha256,mode});}
  for(const name of ['LICENSE','LICENSE-MIT','LICENSE-APACHE','LICENSES/CC-BY-4.0.txt','LICENSES/MIT-0.txt','TRADEMARKS.md','licensing.json'])rows.push({path:'licenses/kelft/'+name,file:safeFile(directory,name),mode:0o644});
  rows.push({path:'README.md',file:safeFile(directory,'INSTALL.md'),mode:0o644},{path:'release.json',file:safeFile(directory,'release.json'),mode:0o644});
  const receipt=components??readJSON(path.join(installation,'rebuild.json'));rows.push({path:'provenance/distribution.json',data:json({schema:'kelft.native-distribution/1',version:identity.version,snapshotID:identity.id,compiler:receipt.compiler,object:receipt.object,policies:receipt.policies,hosts:hosts(installation),...(receipt.componentProducers?{componentProducers:receipt.componentProducers}:{}),seedManifestSHA256:identity.seeds[target].manifestSHA256,hostsRebuilt:false}),mode:0o644});
  rows.sort((a,b)=>a.path<b.path?-1:1);rows.push({path:'runtime-modes.json',data:json({schema:'kelft.runtime-modes/1',files:rows.map(row=>({path:row.path,mode:row.mode}))}),mode:0o644});rows.sort((a,b)=>a.path<b.path?-1:1);requireThat(new Set(rows.map(row=>row.path.toLowerCase())).size===rows.length,'Native package collision');
  const bytes=target.startsWith('windows')?zip(rows):tarGzip(rows);fs.writeFileSync(output,bytes,{flag:'wx'});return {file:path.basename(output),...fileIdentity(output),files:rows.map(row=>({path:row.path,mode:row.mode,...(row.data?{bytes:row.data.length,sha256:sha256(row.data)}:fileIdentity(row.file))}))};
}
