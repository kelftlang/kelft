// Explicit native SDK alternative for hosts without a local Docker socket.
// The configuration is measured before/after every build; PATH is not discovery.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {spawnSync}from'node:child_process';
import {inventorySDK,nativeFileHash}from'./direct-toolchain.mjs';
import {hash,readJson,writeJson,repo}from'./ai/common.mjs';
export function inspectNativeRustSDK(configuration){
 const value=readJson(configuration);assert.equal(value.schema,'kelft-native-rust-sdk/1');assert.ok(path.isAbsolute(value.root));
 const triple=({linux:{x64:'x86_64-unknown-linux-gnu',arm64:'aarch64-unknown-linux-gnu'},win32:{x64:'x86_64-pc-windows-msvc',arm64:'aarch64-pc-windows-msvc'},darwin:{x64:'x86_64-apple-darwin',arm64:'aarch64-apple-darwin'}})[process.platform]?.[process.arch];assert.ok(triple,'unsupported native SDK host');
 const suffix=process.platform==='win32'?'.exe':'',root=fs.realpathSync(value.root),rustc=path.join(root,'bin/rustc'+suffix),cargo=path.join(root,'bin/cargo'+suffix);
 assert.equal(nativeFileHash(rustc),value.rustcSHA256);assert.equal(nativeFileHash(cargo),value.cargoSHA256);
 const version=spawnSync(rustc,['-vV'],{encoding:'utf8',timeout:30000,windowsHide:true});assert.equal(version.status,0,version.stderr||version.error?.message);
 assert.ok(version.stdout.split(/\r?\n/).includes('release: 1.99.0'));assert.ok(version.stdout.split(/\r?\n/).includes('host: '+triple),'SDK must execute natively on the selected architecture');
 assert.equal(inventorySDK(path.join(root,'lib')).sha256,value.libraryIdentity,'native SDK libraries changed');
 return {root,rustc,cargo,triple,version:version.stdout,configurationHash:hash(fs.readFileSync(configuration)),identity:hash(value),provenance:value.provenance??null};
}
export function buildWithNativeRustSDK({configuration,directory,pins,output,linuxWindowsCrossSHA256=null,targetCatalog=null,componentPolicy=null,workspacePolicy=null,testingPolicy=null,rebuildPolicy=null}){
 const sdk=inspectNativeRustSDK(configuration),target=path.join(directory,'rust-target');
 const flags=['--remap-path-prefix='+repo+'=/source','--remap-path-prefix='+path.resolve(directory)+'=/build'];
 if(process.platform==='linux')flags.push('-C','target-feature=+crt-static','-C','link-arg=-Wl,--build-id=none');
 else if(process.platform==='win32')flags.push('-C','target-feature=+crt-static','-C','link-arg=/Brepro');
 else flags.push('-C','link-arg=-Wl,-no_uuid');
 const env={...process.env,RUSTC:sdk.rustc,CARGO_TARGET_DIR:target,KELFT_NATIVE_PINS:pins,SOURCE_DATE_EPOCH:'0',CARGO_ENCODED_RUSTFLAGS:flags.join('\x1f')};delete env.RUSTFLAGS;
 delete env.KELFT_LINUX_WINDOWS_CROSS_SHA256;
 delete env.KELFT_TARGET_CATALOG;delete env.KELFT_COMPONENT_POLICY;if(targetCatalog){assert.ok(componentPolicy);env.KELFT_TARGET_CATALOG=path.resolve(targetCatalog);env.KELFT_COMPONENT_POLICY=path.resolve(componentPolicy);}
 delete env.KELFT_WORKSPACE_POLICY;if(workspacePolicy)env.KELFT_WORKSPACE_POLICY=path.resolve(workspacePolicy);
 delete env.KELFT_REBUILD_POLICY;if(rebuildPolicy)env.KELFT_REBUILD_POLICY=path.resolve(rebuildPolicy);
 delete env.KELFT_TESTING_POLICY;if(testingPolicy)env.KELFT_TESTING_POLICY=path.resolve(testingPolicy);
 if(linuxWindowsCrossSHA256){assert.match(linuxWindowsCrossSHA256,/^sha256:[0-9a-f]{64}$/);assert.equal(process.platform,'linux');assert.equal(process.arch,'x64');env.KELFT_LINUX_WINDOWS_CROSS_SHA256=linuxWindowsCrossSHA256;}
 const args=['--manifest-path',path.join(repo,'driver/Cargo.toml'),'--locked','--offline','--no-default-features','--features','installed-native'];
 const run=command=>{const result=spawnSync(sdk.cargo,command,{encoding:'utf8',cwd:repo,env,windowsHide:true,timeout:300000,maxBuffer:4194304});assert.equal(result.status,0,result.stderr||result.stdout||result.error?.message);return result;};
 const tree=run(['tree',...args]).stdout;assert.doesNotMatch(tree,/wasmtime|wasmtime-wasi|tokio|cranelift/);
 const build=run(['build',...args,'--release','--bin','kelft-native-host','--target',sdk.triple]);fs.writeFileSync(path.join(directory,'native-host-build.log'),build.stdout+build.stderr);
 fs.copyFileSync(path.join(target,sdk.triple,'release/kelft-native-host'+(process.platform==='win32'?'.exe':'')),output);if(process.platform!=='win32')fs.chmodSync(output,0o755);
 assert.deepEqual(inspectNativeRustSDK(configuration),sdk,'native SDK changed during build');
 const result={sdk,dependencyTree:tree,executableSHA256:nativeFileHash(output),wasmEngineLinked:false};writeJson(path.join(directory,'native-sdk-build.json'),result);return result;
}
