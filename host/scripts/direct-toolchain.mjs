// Inventory only: never discovers a linker from PATH or invokes a tool implicitly.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {hash,canonical,writeJson} from './ai/common.mjs';

export const directTargets=JSON.parse(fs.readFileSync(new URL('../native/direct-targets.json',import.meta.url),'utf8'));
export function directProfile(id){const p=directTargets.profiles.find(p=>p.id===id);if(!p)throw new Error('unsupported direct native profile '+id);return p;}
function inside(root,file){const r=path.relative(root,file);return r===''||r!=='..'&&!r.startsWith('..'+path.sep)&&!path.isAbsolute(r);}
export function nativeFileHash(file){
  const fd=fs.openSync(file,'r');try{
    const before=fs.fstatSync(fd,{bigint:true});if(!before.isFile())throw new Error('toolchain input must be a regular file');
    const digest=createHash('sha256'),buffer=Buffer.alloc(1024*1024);let n;while((n=fs.readSync(fd,buffer,0,buffer.length,null))>0)digest.update(buffer.subarray(0,n));
    const after=fs.fstatSync(fd,{bigint:true});if(before.size!==after.size||before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs)throw new Error('toolchain input changed while hashing');
    return 'sha256:'+digest.digest('hex');
  }finally{fs.closeSync(fd);}
}
export function inventorySDK(directory){
  const root=fs.realpathSync(directory),files=[];
  function walk(folder){for(const name of fs.readdirSync(folder).sort()){
    const file=path.join(folder,name),relative=path.relative(root,file).split(path.sep).join('/'),stat=fs.lstatSync(file);
    if(stat.isSymbolicLink()){
      const resolved=fs.realpathSync(file);if(!inside(root,resolved))throw new Error('SDK symlink escapes inventory: '+relative);
      files.push({path:relative,kind:'symlink',target:path.relative(root,resolved).split(path.sep).join('/')});
    }else if(stat.isDirectory())walk(file);
    else if(stat.isFile())files.push({path:relative,kind:'file',size:stat.size,sha256:nativeFileHash(file)});
    else throw new Error('non-file SDK input: '+relative);
  }}
  walk(root);if(!files.some(f=>f.kind==='file'))throw new Error('SDK inventory is empty');return {sha256:hash(files),files};
}
export function inventoryNativeToolchain(config){
  const profile=directProfile(config.profile);
  for(const key of ['linker','sdk'])if(typeof config[key]!=='string'||!path.isAbsolute(config[key]))throw new Error('absolute '+key+' path required');
  if(!Array.isArray(config.flags)||!config.flags.every(f=>typeof f==='string'))throw new Error('explicit linker flags required');
  if(profile.platform==='macos'&&(!config.signer||!Array.isArray(config.signingFlags)))throw new Error('pinned macOS ad-hoc signer and flags required');
  if(config.signer&&(!path.isAbsolute(config.signer)||!config.signingFlags.every(f=>typeof f==='string')))throw new Error('absolute signer path and explicit signing flags required');
  if(config.signerHelper&&(!config.signer||typeof config.signerHelper!=='string'||!path.isAbsolute(config.signerHelper)))throw new Error('absolute signing helper path and signer required');
  const measure=()=>({linker:{sha256:nativeFileHash(config.linker)},sdk:inventorySDK(config.sdk),...(config.signer?{signer:{sha256:nativeFileHash(config.signer)}}:{}),...(config.signerHelper?{signerHelper:{sha256:nativeFileHash(config.signerHelper)}}:{})});
  const measured=measure();if(canonical(measured)!==canonical(measure()))throw new Error('linker/SDK changed during inventory');
  const inputs={profile:profile.id,architecture:profile.architecture,platform:profile.platform,format:profile.format,abi:profile.abi,runtimeABI:directTargets.runtimeABI,baseline:profile.baseline,...measured,flags:[...config.flags],...(config.signer?{signingFlags:[...config.signingFlags]}:{})};
  // Checkout and installation paths are not part of the portable toolchain identity.
  return {schema:'kelft-direct-toolchain/1',identity:hash(inputs),inputs};
}
export function verifyNativeToolchain(config,manifest){
  if(manifest.schema!=='kelft-direct-toolchain/1'||manifest.identity!==hash(manifest.inputs))throw new Error('invalid direct toolchain manifest');
  if(canonical(inventoryNativeToolchain(config))!==canonical(manifest))throw new Error('direct linker/SDK/signing inputs changed');return manifest.identity;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [command,configuration,output]=process.argv.slice(2);if(!['inventory','verify'].includes(command)||!configuration||!output)throw new Error('usage: direct-toolchain.mjs inventory|verify CONFIG.json MANIFEST.json');
  const config=JSON.parse(fs.readFileSync(configuration,'utf8'));
  if(command==='inventory')writeJson(output,inventoryNativeToolchain(config));else verifyNativeToolchain(config,JSON.parse(fs.readFileSync(output,'utf8')));
}
