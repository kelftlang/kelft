// Native, locked, offline builds; the coordinator and boundary omit WASI.
import {treeHash} from './build-inputs.mjs';
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import {repo,hash,writeJson} from './ai/common.mjs';
import {inventorySDK,nativeFileHash} from './direct-toolchain.mjs';
export function buildWindowsInstalledHost({directory,packageRoot,compiler,configuration,run,targetCatalog=null,componentPolicy=null,workspacePolicy=null,testingPolicy=null,rebuildPolicy=null,hostSystemInputs=false}){
 assert.equal(process.platform,'win32');assert.ok(['x64','arm64'].includes(process.arch));fs.mkdirSync(directory,{recursive:true});
 const workspacePolicySHA256=workspacePolicy?hash(fs.readFileSync(workspacePolicy)):null;
 const hostInputs=['driver/Cargo.toml','driver/Cargo.lock','driver/build.rs','driver/release.json'],sourceHash=treeHash(repo,['driver/src'],hostInputs),rebuildPolicySHA256=rebuildPolicy?hash(fs.readFileSync(rebuildPolicy)):null;
 const triple=(process.arch==='arm64'?'aarch64':'x86_64')+'-pc-windows-msvc',sdk=process.env.KELFT_NATIVE_RUST_TOOLCHAIN??'1.99.0-'+triple;
 const version=run('rustup',['run',sdk,'rustc','-vV'],'rust-sdk').stdout;assert.ok(version.includes('release: 1.99.0\n')||version.includes('release: 1.99.0\r\n'));assert.ok(version.split(/\r?\n/).includes('host: '+triple));
 const rustc=run('rustup',['which','--toolchain',sdk,'rustc'],'rust-path').stdout.trim();
 const sysroot=run(rustc,['--print','sysroot'],'installed-rust-sysroot').stdout.trim(),rustLibraries=inventorySDK(path.join(sysroot,'lib')),cargoPath=run('rustup',['which','--toolchain',sdk,'cargo'],'installed-cargo-path').stdout.trim(),cargoSHA256=nativeFileHash(cargoPath),rustcSHA256=nativeFileHash(rustc),lockSHA256=nativeFileHash(path.join(repo,'driver/Cargo.lock'));
 const pins=path.join(directory,'pins.rs'),compilerHash=hash(fs.readFileSync(compiler)),configurationHash=hash(fs.readFileSync(configuration));
 const prefix='pub(crate) const COMPILER_SHA256:&str='+JSON.stringify(compilerHash)+';\npub(crate) const WINDOWS_LINKER_POLICY_SHA256:&str='+JSON.stringify(configurationHash)+';\n';fs.writeFileSync(pins,prefix);
 const flags=['-C','target-feature=+crt-static','-C','link-arg=/Brepro','-C','link-arg=/DEBUG:NONE','-C','link-arg=/PDB:NONE','--remap-path-prefix='+repo+'=/source'];
 const env={...process.env,LINK:'',_LINK_:'',CARGO_NET_OFFLINE:'true',CARGO_TARGET_DIR:path.join(directory,'target'),KELFT_NATIVE_PINS:pins,SOURCE_DATE_EPOCH:'0',CARGO_ENCODED_RUSTFLAGS:flags.join('\u001f')};delete env.RUSTFLAGS;delete env.KELFT_OPTIONAL_ENGINE_PROFILES_SHA256;
 delete env.KELFT_TARGET_CATALOG;delete env.KELFT_COMPONENT_POLICY;
 delete env.KELFT_WORKSPACE_POLICY;if(workspacePolicy)env.KELFT_WORKSPACE_POLICY=path.resolve(workspacePolicy);
 delete env.KELFT_REBUILD_POLICY;if(rebuildPolicy)env.KELFT_REBUILD_POLICY=path.resolve(rebuildPolicy);
 delete env.KELFT_TESTING_POLICY;if(testingPolicy)env.KELFT_TESTING_POLICY=path.resolve(testingPolicy);
 delete env.KELFT_DEVELOPMENT_WINDOWS_SYSTEM_INPUTS;
 if(hostSystemInputs){assert.ok(testingPolicy,'host System32 binding requires a development testing image');env.KELFT_DEVELOPMENT_WINDOWS_SYSTEM_INPUTS='1';}
 if(targetCatalog){assert.ok(componentPolicy);env.KELFT_TARGET_CATALOG=path.resolve(targetCatalog);env.KELFT_COMPONENT_POLICY=path.resolve(componentPolicy);}
 const engineManifest=path.join(packageRoot,'rootfs/control/engine-profiles.json'),engineProfilesHash=fs.existsSync(engineManifest)?hash(fs.readFileSync(engineManifest)):null;if(engineProfilesHash)env.KELFT_OPTIONAL_ENGINE_PROFILES_SHA256=engineProfilesHash;
 delete env.KELFT_WINDOWS_LINUX_CROSS_SHA256;
 const crossManifest=path.join(packageRoot,'rootfs/control/cross-linux-x86_64.json'),crossProfileHash=fs.existsSync(crossManifest)?hash(fs.readFileSync(crossManifest)):null;
 if(crossProfileHash){assert.equal(process.arch,'x64');env.KELFT_WINDOWS_LINUX_CROSS_SHA256=crossProfileHash;}
 const cargo=['run',sdk,'cargo'],base=['--manifest-path',path.join(repo,'driver/Cargo.toml'),'--locked','--offline','--no-default-features','--features','installed-native,windows-host'];
 const tree=run('rustup',[...cargo,'tree',...base],'native-host-dependencies',{env}).stdout;assert.doesNotMatch(tree,/wasmtime|wasmtime-wasi|tokio|cranelift/);
 if(hostSystemInputs)run('rustup',[...cargo,'test',...base,'--release','--target',triple,'--lib','windows_linker::tests','--','--test-threads=1'],'development-linker-controls',{env,timeout:300000});
 const bin=path.join(packageRoot,'bin');fs.mkdirSync(bin,{recursive:true});
 const build=(name)=>{run('rustup',[...cargo,'build',...base,'--release','--target',triple,'--bin',name],'build-'+name,{env,timeout:300000});return path.join(directory,'target',triple,'release',name+'.exe');};
 const boundary=build('kelft-windows-installed-boundary'),boundaryHash=hash(fs.readFileSync(boundary));fs.copyFileSync(boundary,path.join(bin,'kelft-boundary.exe'));
 fs.writeFileSync(pins,prefix+'pub(crate) const BOUNDARY_SHA256:&str='+JSON.stringify(boundaryHash)+';\n');
 const coordinator=build('kelft-native-host');fs.copyFileSync(coordinator,path.join(bin,'kelft.exe'));assert.equal(hash(fs.readFileSync(compiler)),compilerHash);assert.equal(hash(fs.readFileSync(configuration)),configurationHash);
 if(engineProfilesHash)assert.equal(hash(fs.readFileSync(engineManifest)),engineProfilesHash);
 if(crossProfileHash)assert.equal(hash(fs.readFileSync(crossManifest)),crossProfileHash);
 if(workspacePolicy)assert.equal(hash(fs.readFileSync(workspacePolicy)),workspacePolicySHA256);
 assert.equal(nativeFileHash(rustc),rustcSHA256);assert.equal(nativeFileHash(cargoPath),cargoSHA256);assert.deepEqual(inventorySDK(path.join(sysroot,'lib')),rustLibraries);assert.equal(nativeFileHash(path.join(repo,'driver/Cargo.lock')),lockSHA256);
 assert.equal(treeHash(repo,['driver/src'],hostInputs),sourceHash,'native host sources changed');if(rebuildPolicy)assert.equal(hash(fs.readFileSync(rebuildPolicy)),rebuildPolicySHA256);
 const record={sourceHash,rebuildPolicySHA256,schema:'kelft-windows-installed-host-build/1',triple,version,cargo:{path:cargoPath,sha256:cargoSHA256},rustLibraries,lockSHA256,rustc:{path:rustc,sha256:hash(fs.readFileSync(rustc))},compilerHash,configurationHash,boundaryHash,coordinatorHash:hash(fs.readFileSync(coordinator)),workspacePolicySHA256,engineProfilesHash,crossProfileHash,systemInputBinding:hostSystemInputs?'development-host-system32/1':'package-sha256/1',wasmEngineLinked:false,dependencyTree:tree};writeJson(path.join(directory,'report.json'),record);return record;
}
