// Select a prepared native SDK, never an emulated or mutable-tag fallback.
import assert from 'node:assert/strict';
export function nativeNodeDistribution(lock,profile){
 assert.equal(lock.schema,'kelft-artifact-tools/1');assert.equal(lock.node.version,'v24.22.0');
 assert.ok(['windows-x86_64','windows-arm64','macos-x86_64','macos-arm64'].includes(profile),'explicit native distribution required');
 const windows=profile.startsWith('windows-'),architecture=profile.endsWith('arm64')?'arm64':'x86_64',vendorArchitecture=architecture==='arm64'?'arm64':'x64';
 const expected=windows?'win-'+vendorArchitecture+'/node.exe':'node-'+lock.node.version+'-darwin-'+vendorArchitecture+'.tar.gz',input=lock.node.distributions?.[profile];
 assert.ok(input,'native Node distribution has no reviewed pin');assert.deepEqual(Object.keys(input).sort(),['file','format','sha256']);assert.equal(input.file,expected);assert.equal(input.format,windows?'pe':'tar.gz');assert.match(input.sha256,/^[a-f0-9]{64}$/);
 return {...input,profile,architecture,version:lock.node.version,url:'https://nodejs.org/dist/'+lock.node.version+'/'+input.file,member:windows?null:expected.slice(0,-7)+'/bin/node'};
}
export function requireNativeNodeImage(bytes,profile){
 assert.ok(['windows-x86_64','windows-arm64','macos-x86_64','macos-arm64'].includes(profile));assert.ok(bytes.length>=64&&bytes.length<=268435456);const arm=profile.endsWith('arm64');
 if(profile.startsWith('windows-')){
  assert.equal(bytes.toString('ascii',0,2),'MZ');const offset=bytes.readUInt32LE(60);assert.ok(offset>=64&&offset<=bytes.length-264);assert.equal(bytes.toString('ascii',offset,offset+4),'PE\0\0');assert.equal(bytes.readUInt16LE(offset+4),arm?0xaa64:0x8664);assert.equal(bytes.readUInt16LE(offset+24),0x20b);assert.ok(bytes.readUInt16LE(offset+22)&2);assert.equal(bytes.readUInt16LE(offset+22)&0x2000,0);
 }else{
  assert.equal(bytes.readUInt32LE(0),0xfeedfacf);assert.equal(bytes.readUInt32LE(4),arm?0x0100000c:0x01000007);assert.equal(bytes.readUInt32LE(8)&0x00ffffff,arm?0:3);assert.equal(bytes.readUInt32LE(12),2);
 }
 return profile;
}
export function nativeNodeSDK(lock,architecture){
 assert.equal(lock.schema,'kelft-artifact-tools/1');assert.ok(['x86_64','arm64'].includes(architecture),'unsupported native Node architecture');
 assert.equal(lock.node.version,'v24.22.0');
 const platform='linux/'+(architecture==='arm64'?'arm64':'amd64');
 const image=lock.node.platformImages?.[platform]??(architecture==='x86_64'?lock.node.image:undefined);
 assert.ok(typeof image==='string'&&/^node@sha256:[a-f0-9]{64}$/.test(image),'explicit digest-pinned native Node image required');
 if(architecture==='x86_64')assert.equal(image,lock.node.image,'legacy x64 Node pin differs');
 return {image,platform,version:lock.node.version};
}
export function nativeRustSDK(lock,architecture){
 assert.equal(lock.schema,'kelft-artifact-tools/1');assert.ok(['x86_64','arm64'].includes(architecture),'unsupported native Rust architecture');assert.equal(lock.rust.version,'1.99.0');
 const platform='linux/'+(architecture==='arm64'?'arm64':'amd64'),triple=(architecture==='arm64'?'aarch64':'x86_64')+'-unknown-linux-gnu';
 const image=lock.rust.platformImages?.[platform]??(architecture==='x86_64'?lock.rust.image:undefined);
 assert.ok(typeof image==='string'&&/^rust@sha256:[a-f0-9]{64}$/.test(image),'explicit digest-pinned native Rust image required');
 if(architecture==='x86_64')assert.equal(image,lock.rust.image,'legacy x64 SDK pin differs');
 return {image,platform,triple,version:lock.rust.version};
}
