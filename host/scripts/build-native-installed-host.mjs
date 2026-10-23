// Build-time only. The installed native host contains no WASI engine.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';
import {treeHash} from './build-inputs.mjs';
import {repo,hash,readJson,writeJson} from './ai/common.mjs';
import {buildWithNativeRustSDK} from './native-rust-sdk.mjs';
import {nativeRustSDK} from './native-artifact-tools.mjs';
export function buildNativeInstalledHost({directory,boundary,compiler,output,crossProfileSHA256=null,targetCatalog=null,componentPolicy=null,workspacePolicy=null,testingPolicy=null,rebuildPolicy=null}){
 if(crossProfileSHA256)assert.match(crossProfileSHA256,/^sha256:[0-9a-f]{64}$/);
 assert.equal(process.platform,'linux');assert.ok(['x64','arm64'].includes(process.arch));
 const architecture=process.arch==='arm64'?'aarch64':'x86_64',triple=architecture+'-unknown-linux-gnu',machine=process.arch==='arm64'?183:62;
 assert.equal(fs.readFileSync('/proc/self/exe').readUInt16LE(18),machine);
 const inputs=['driver/Cargo.toml','driver/release.json','driver/Cargo.lock','driver/build.rs','native/artifact-tools.lock.json','native/resource-contracts.json','scripts/native-artifact-tools.mjs','package.json'];
 const sourceHash=treeHash(repo,['driver/src'],inputs);
 const lock=readJson(path.join(repo,'native/artifact-tools.lock.json')),{image}=nativeRustSDK(lock,process.arch==='arm64'?'arm64':'x86_64');
 assert.match(image,/@sha256:[0-9a-f]{64}$/);assert.equal(lock.rust.version,'1.99.0');
 const boundarySHA256=hash(fs.readFileSync(boundary)),compilerSHA256=hash(fs.readFileSync(compiler));
 const pins='pub(crate) const BOUNDARY_SHA256:&str='+JSON.stringify(boundarySHA256)+';\npub(crate) const COMPILER_SHA256:&str='+JSON.stringify(compilerSHA256)+';\n';
 fs.writeFileSync(path.join(directory,'installed-pins.rs'),pins);
 if(workspacePolicy){const destination=path.join(directory,'workspace-policy');if(path.resolve(workspacePolicy)!==path.resolve(destination))fs.copyFileSync(workspacePolicy,destination);workspacePolicy=destination;}
 if(testingPolicy){const destination=path.join(directory,'testing-policy');if(path.resolve(testingPolicy)!==path.resolve(destination))fs.copyFileSync(testingPolicy,destination);testingPolicy=destination;}
 if(rebuildPolicy){const destination=path.join(directory,'rebuild-policy');if(path.resolve(rebuildPolicy)!==path.resolve(destination))fs.copyFileSync(rebuildPolicy,destination);rebuildPolicy=destination;}
 if(process.env.KELFT_NATIVE_RUST_SDK){
  const native=buildWithNativeRustSDK({configuration:process.env.KELFT_NATIVE_RUST_SDK,directory,pins:path.join(directory,'installed-pins.rs'),output,linuxWindowsCrossSHA256:crossProfileSHA256,targetCatalog,componentPolicy,workspacePolicy,testingPolicy,rebuildPolicy});
  assert.equal(fs.readFileSync(output).readUInt16LE(18),machine,'native host output architecture');
  for(const [flag,forbidden] of [['-d',/\(NEEDED\)/],['-l',/INTERP/]]){const r=spawnSync('/usr/bin/readelf',[flag,output],{encoding:'utf8'});assert.equal(r.status,0);assert.doesNotMatch(r.stdout,forbidden);}
  assert.equal(hash(fs.readFileSync(boundary)),boundarySHA256);assert.equal(hash(fs.readFileSync(compiler)),compilerSHA256);
  assert.equal(treeHash(repo,['driver/src'],inputs),sourceHash);
  const result={sourceHash,schema:'kelft-installed-native-host-build/1',...native,boundarySHA256,compilerSHA256,static:true};writeJson(path.join(directory,'native-host-build.json'),result);return result;
 }
 const target=path.join(directory,'rust-target');fs.mkdirSync(target);
 const args=['run','--rm','--platform','linux/'+(process.arch==='arm64'?'arm64':'amd64'),'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--user',process.getuid()+':'+process.getgid(),'--tmpfs','/tmp:rw,nosuid,size=128m',
 '--mount','type=bind,source='+repo+',target=/work,readonly','--mount','type=bind,source='+path.resolve(directory)+',target=/out',
 '--mount','type=bind,source='+path.join(repo,'.cache/artifact-cargo/home')+',target=/cargo',
 '--env','CARGO_HOME=/cargo','--env','CARGO_TARGET_DIR=/out/rust-target','--env','KELFT_NATIVE_PINS=/out/installed-pins.rs',
 '--env','SOURCE_DATE_EPOCH=0','--env','RUSTFLAGS=-C target-feature=+crt-static -C link-arg=-Wl,--build-id=none --remap-path-prefix=/work=/source --remap-path-prefix=/out=/build',image];
 if(crossProfileSHA256)args.splice(args.length-1,0,'--env','KELFT_LINUX_WINDOWS_CROSS_SHA256='+crossProfileSHA256);
 if(workspacePolicy)args.splice(args.length-1,0,'--env','KELFT_WORKSPACE_POLICY=/out/workspace-policy');
 if(rebuildPolicy)args.splice(args.length-1,0,'--env','KELFT_REBUILD_POLICY=/out/rebuild-policy');
 if(testingPolicy)args.splice(args.length-1,0,'--env','KELFT_TESTING_POLICY=/out/testing-policy');
 if(targetCatalog){assert.ok(componentPolicy);for(const [key,file] of [['KELFT_TARGET_CATALOG',targetCatalog],['KELFT_COMPONENT_POLICY',componentPolicy]]){assert.ok(path.resolve(file).startsWith(path.resolve(directory)+path.sep));args.splice(args.length-1,0,'--env',key+'=/out/'+path.relative(directory,file).split(path.sep).join('/'));}}
 const run=(command)=>{const r=spawnSync('docker',[...args,...command],{cwd:repo,encoding:'utf8',timeout:300000,maxBuffer:4*1024*1024});assert.equal(r.status,0,r.stderr||r.stdout||r.error?.message);return r;};
 const version=run(['rustc','-vV']).stdout.trim();assert.ok(version.includes('release: '+lock.rust.version+'\n'));assert.ok(version.split('\n').includes('host: '+triple),'Rust SDK must execute natively on the package architecture');
 const tree=run(['cargo','tree','--manifest-path','/work/driver/Cargo.toml','--locked','--offline','--no-default-features','--features','installed-native']).stdout;
 assert.doesNotMatch(tree,/wasmtime|wasmtime-wasi|tokio|cranelift/);
 const built=run(['cargo','build','--manifest-path','/work/driver/Cargo.toml','--release','--locked','--offline','--no-default-features','--features','installed-native','--bin','kelft-native-host','--target',triple]);fs.writeFileSync(path.join(directory,'native-host-build.log'),built.stdout+built.stderr);
 fs.copyFileSync(path.join(target,triple,'release/kelft-native-host'),output);fs.chmodSync(output,0o755);
 assert.equal(fs.readFileSync(output).readUInt16LE(18),machine,'native host output architecture');
 const dynamic=spawnSync('/usr/bin/readelf',['-d',output],{encoding:'utf8'});assert.equal(dynamic.status,0,dynamic.stderr);assert.doesNotMatch(dynamic.stdout,/\(NEEDED\)/);const segments=spawnSync('/usr/bin/readelf',['-l',output],{encoding:'utf8'});assert.equal(segments.status,0,segments.stderr);assert.doesNotMatch(segments.stdout,/INTERP/);
 assert.equal(hash(fs.readFileSync(boundary)),boundarySHA256);assert.equal(hash(fs.readFileSync(compiler)),compilerSHA256);
 assert.equal(treeHash(repo,['driver/src'],inputs),sourceHash,'native host build inputs changed');
 const result={sourceHash,schema:'kelft-installed-native-host-build/1',sdk:{image,version,triple},boundarySHA256,compilerSHA256,executableSHA256:hash(fs.readFileSync(output)),static:true,wasmEngineLinked:false,dependencyTree:tree};writeJson(path.join(directory,'native-host-build.json'),result);return result;
}
