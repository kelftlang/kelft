// Development/export mechanisms. Installed selection and archive acceptance are
// implemented by selfhost/toolchain/targets.kelft, never by this Node script.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import zlib from 'node:zlib';
import {hash,canonical,treeFiles} from './ai/common.mjs';
import {treeHash} from './build-inputs.mjs';
const MAX=512<<20;
export const archiveContract='kelft.distribution-archive/1',boundaryContract='kelft.installed-targets/1';
export function stageDistributionNotices({packageRoot,host,directory}){
 const targetPrefix=host==='linux-x86_64'?'cross/windows-x86_64/licenses/':'rootfs/cross/linux-x86_64/licenses/';
 for(const name of treeFiles(directory)){assert.ok(/^[A-Za-z0-9._/-]+$/.test(name)&&!name.split('/').includes('..'));for(const prefix of ['licenses/',targetPrefix]){const output=path.join(packageRoot,prefix,name);fs.mkdirSync(path.dirname(output),{recursive:true});fs.copyFileSync(path.join(directory,name),output);if(process.platform==='linux')fs.chmodSync(output,0o644);}}
}
export function distributionHeader(name,size,mode){
 assert.ok(Buffer.byteLength(name)<=100&&size<=256<<20);const b=Buffer.alloc(512);b.write(name,0,100);
 const oct=(at,n,value)=>b.write(value.toString(8).padStart(n-1,'0')+'\0',at,n,'ascii');oct(100,8,mode);oct(108,8,0);oct(116,8,0);oct(124,12,size);oct(136,12,0);b.fill(32,148,156);b[156]=48;b.write('ustar\0',257,6);b.write('00',263,2);b.write(b.reduce((n,x)=>n+x,0).toString(8).padStart(6,'0')+'\0 ',148,8);return b;
}
export function distributionArchive(rows){
 assert.ok(rows.length>0&&rows.length<=8192);let total=1024;const blocks=[];
 for(const row of rows){const bytes=row.bytes??fs.readFileSync(row.source);assert.equal(bytes.length,row.size);if(row.sha256)assert.equal(hash(bytes),row.sha256);total+=512+Math.ceil(bytes.length/512)*512;assert.ok(total<=MAX);blocks.push(distributionHeader(row.path,bytes.length,row.mode),bytes);if(bytes.length%512)blocks.push(Buffer.alloc(512-bytes.length%512));}
 blocks.push(Buffer.alloc(1024));const gzip=zlib.gzipSync(Buffer.concat(blocks),{level:9,mtime:0});gzip[9]=255;return gzip;
}
const publicTarget=t=>t==='linux-x86_64'?'x86_64-linux':'x86_64-windows';
export function componentPath(host,name){return host==='linux-x86_64'?name.startsWith('cross/windows-x86_64/'):name.startsWith('rootfs/cross/linux-x86_64/')||name==='rootfs/control/cross-linux-x86_64.json';}
export function prepareTargetCatalog({packageRoot,directory,host,version=JSON.parse(fs.readFileSync(new URL('../package.json',import.meta.url))).version}){
 assert.ok(['linux-x86_64','windows-x86_64'].includes(host));fs.mkdirSync(directory,{recursive:true});
 const target=host==='linux-x86_64'?'windows-x86_64':'linux-x86_64',compilerSHA256=hash(fs.readFileSync(path.join(packageRoot,host==='linux-x86_64'?'rootfs/compiler':'rootfs/compiler.exe')));
 const profile=host==='linux-x86_64'?'cross/windows-x86_64/manifest.json':'rootfs/control/cross-linux-x86_64.json';
 const names=treeFiles(packageRoot).filter(name=>componentPath(host,name)).sort();assert.ok(names.includes(profile),'prepare the cross profile before constructing the release catalog');
 const files=names.map(name=>{const source=path.join(packageRoot,name),stat=fs.lstatSync(source);assert.ok(stat.isFile()&&stat.size<=256<<20);const mode=host==='linux-x86_64'?stat.mode&511:name.endsWith('.exe')?0o755:0o644;return {path:name,size:stat.size,mode,sha256:hash(fs.readFileSync(source))};});
 const linkerProfile=host==='linux-x86_64'?'lld-coff/1':'lld-elf-static/1',profileSHA256=hash(fs.readFileSync(path.join(packageRoot,profile)));
 const metadata=Buffer.from(canonical({schema:'kelft.target-pack/1',archiveContract,boundaryContract,version,host,target,compilerSHA256,linkerProfile,profileSHA256})+'\n');
 const bytes=distributionArchive([{path:'component.json',size:metadata.length,mode:0o644,bytes:metadata},...files.map(f=>({...f,source:path.join(packageRoot,f.path)}))]);
 const filename=`kelft-${version}-${publicTarget(host)}-target-${publicTarget(target)}.tar.gz`;fs.writeFileSync(path.join(directory,filename),bytes);
 const catalog={schema:'kelft.target-catalog/1',archiveContract,boundaryContract,version,host,compilerSHA256,components:[{target,linkerProfile,profileSHA256,metadataSHA256:hash(metadata),archive:{file:filename,size:bytes.length,sha256:hash(bytes)},files}]};
 const file=path.join(directory,'target-catalog.json');fs.writeFileSync(file,canonical(catalog)+'\n');fs.writeFileSync(path.join(packageRoot,'target-catalog.json'),canonical(catalog)+'\n');fs.mkdirSync(path.join(packageRoot,'.kelft-targets'),{recursive:true});fs.writeFileSync(path.join(packageRoot,'.kelft-targets/lock'),'');if(process.platform==='linux')fs.chmodSync(path.join(packageRoot,'.kelft-targets/lock'),0o644);return {file,catalog,sha256:hash(fs.readFileSync(file)),archive:path.join(directory,filename)};
}
export function exportDistributions({packageRoot,directory,catalogFile,bundle='native'}){
 assert.ok(['native','complete','target','all'].includes(bundle));
 const catalog=JSON.parse(fs.readFileSync(catalogFile)),host=catalog.host,component=catalog.components[0];assert.equal(hash(fs.readFileSync(path.join(packageRoot,host==='linux-x86_64'?'rootfs/compiler':'rootfs/compiler.exe'))),catalog.compilerSHA256);
 fs.mkdirSync(directory,{recursive:true});const all=treeFiles(packageRoot).sort().map(name=>{const file=path.join(packageRoot,name),s=fs.lstatSync(file);assert.ok(s.isFile());let mode=host==='linux-x86_64'?s.mode&511:name.startsWith('bin/')||name==='rootfs/compiler.exe'?0o755:0o644;return {path:name,source:file,size:s.size,mode,sha256:hash(fs.readFileSync(file))};});
 const core=all.filter(r=>!componentPath(host,r.path)&&(!r.path.startsWith('.kelft-targets/')||r.path==='.kelft-targets/lock')&&!r.path.startsWith('engines/')&&!r.path.startsWith('rootfs/engines/')&&r.path!=='rootfs/control/engine-profiles.json');
 // Attach first-party terms to new exports without rewriting a prepared package or catalog.
 const termsRoot=path.resolve(import.meta.dirname,'..'),terms=['LICENSE','LICENSE-MIT','LICENSE-APACHE','LICENSES/CC-BY-4.0.txt','LICENSES/MIT-0.txt','licensing.json','TRADEMARKS.md','docs/licensing.md'];
 for(const name of terms){const source=path.join(termsRoot,name),bytes=fs.readFileSync(source),destination='licenses/kelft/'+name,existing=core.find(r=>r.path===destination);if(existing)assert.equal(existing.sha256,hash(bytes),'prepared Kelft license terms differ; prepare a new package');else core.push({path:destination,source,size:bytes.length,mode:0o644,sha256:hash(bytes)});}
 core.sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
 const installed=new Map(all.map(r=>[r.path,r]));for(const f of component.files){assert.equal(installed.get(f.path)?.sha256,f.sha256);}
 const receipt=Buffer.from(component.archive.sha256+'\n'),complete=[...core,...component.files.map(f=>({...f,source:path.join(packageRoot,f.path)})),{path:'.kelft-targets/'+component.target+'.receipt',mode:0o644,size:receipt.length,bytes:receipt}].sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
 const variants={native:core,complete};const artifacts=[];
 for(const [kind,rows] of Object.entries(variants)){if(bundle!=='all'&&bundle!==kind)continue;const bytes=distributionArchive(rows),name=`kelft-${catalog.version}-${publicTarget(host)}-${kind}.tar.gz`;fs.writeFileSync(path.join(directory,name),bytes);artifacts.push({kind,file:name,sha256:hash(bytes),compressedBytes:bytes.length,archiveBytes:1024+rows.reduce((n,r)=>n+512+Math.ceil(r.size/512)*512,0),payloadBytes:rows.reduce((n,r)=>n+r.size,0)});}
 if(bundle==='all'||bundle==='target')artifacts.push({kind:'target',...component.archive,compressedBytes:component.archive.size,archiveBytes:1024+512+Math.ceil(Buffer.byteLength(canonical({schema:'kelft.target-pack/1',archiveContract,boundaryContract,version:catalog.version,host,target:component.target,compilerSHA256:catalog.compilerSHA256,linkerProfile:component.linkerProfile,profileSHA256:component.profileSHA256})+'\n')/512)*512+component.files.reduce((n,r)=>n+512+Math.ceil(r.size/512)*512,0),payloadBytes:component.files.reduce((n,r)=>n+r.size,0)});
 const repo=path.resolve(import.meta.dirname,'..'),sourceIdentity=treeHash(repo,['driver/src','selfhost','native/standalone'],['driver/Cargo.lock','driver/Cargo.toml','driver/build.rs','scripts/native-distribution.mjs','selfhost/toolchain/targets.kelft',...terms]);
 const coreFiles=core.map(({source,...r})=>r),notices=[...coreFiles,...component.files].filter(r=>/license|copyright|notice/i.test(r.path));
 const report={schema:'kelft.distribution/1',archiveContract,boundaryContract,version:catalog.version,host,catalogSHA256:hash(fs.readFileSync(catalogFile)),compilerSHA256:catalog.compilerSHA256,defaultBundle:'native',artifacts,coreFiles,componentFiles:component.files,licenseNotices:notices,licenseClosureReviewed:false,provenance:{schema:'kelft.distribution-provenance/1',sourceIdentity,cargoLockSHA256:hash(fs.readFileSync(path.join(repo,'driver/Cargo.lock'))),artifactsSDKLockSHA256:hash(fs.readFileSync(path.join(repo,'native/artifact-tools.lock.json'))),networkAtBuild:'none-required',signed:false},certification:{affectedEvidence:'requires-fresh-collection',historicalCertificatesModified:false},nativeCertified:false,releaseEligible:false};
 const inventory={schema:'kelft.distribution-inventory/1',host,compilerSHA256:catalog.compilerSHA256,core:coreFiles,components:catalog.components.map(c=>({target:c.target,linkerProfile:c.linkerProfile,archive:c.archive,files:c.files})),licenseNotices:notices,licenseClosureReviewed:false};
 fs.writeFileSync(path.join(directory,'inventory.json'),canonical(inventory)+'\n');fs.writeFileSync(path.join(directory,'provenance.json'),canonical(report.provenance)+'\n');fs.writeFileSync(path.join(directory,'SHA256SUMS'),artifacts.map(a=>`${a.sha256.slice(7)}  ${a.file}\n`).join(''));fs.writeFileSync(path.join(directory,'distribution.json'),canonical(report)+'\n');return report;
}
