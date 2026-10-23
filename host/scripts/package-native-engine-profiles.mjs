// Build-time materialization of independent, explicit engine namespaces.
import {nativeLinuxProfile} from './native-linux-profile.mjs';
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {hash,readJson,writeJson,safePath} from './ai/common.mjs';
export function stageEngineProfiles({runtimeBundle,destination,compiler,maximum}) {
 const manifestFile=path.join(runtimeBundle,'manifest.json'),source=fs.readFileSync(manifestFile),manifest=JSON.parse(source);
 assert.equal(manifest.schema,'kelft-artifact-runtimes/1');assert.equal(manifest.platform,'linux');assert.equal(manifest.architecture,nativeLinuxProfile().architecture);
 assert.deepEqual(Object.keys(manifest).sort(),['architecture','platform','runtimes','schema']);
 const result={};
 for(const [target,runtime] of Object.entries(manifest.runtimes)){
  assert.ok(['javascript','wasm'].includes(target));assert.deepEqual(Object.keys(runtime).sort(),['dependencies','executable','versionArgs','versionStdout']);
  assert.deepEqual(runtime.versionArgs,[target==='javascript'?'--version':'version']);assert.equal(typeof runtime.versionStdout,'string');assert.ok(runtime.versionStdout.length>0&&runtime.versionStdout.length<=4096);
  assert.ok(Array.isArray(runtime.dependencies)&&runtime.dependencies.length<=128);
  const root=path.join(destination,'engines',target);assert.equal(fs.existsSync(root),false);fs.mkdirSync(root,{recursive:true});
  const copy=(file,name,mode)=>{const to=safePath(root,name);fs.mkdirSync(path.dirname(to),{recursive:true});fs.copyFileSync(file,to);fs.chmodSync(to,mode);};
  copy(compiler,'compiler',0o755);copy(maximum,'control/maximum.json',0o644);
  const seen=new Set();
  const materialize=(input,guest)=>{
   assert.deepEqual(Object.keys(input).sort(),['path','sha256']);assert.match(input.sha256,/^[0-9a-f]{64}$/);
   assert.ok(typeof input.path==='string'&&path.posix.isAbsolute(input.path)&&!input.path.includes('\0')&&path.posix.normalize(input.path)===input.path);
   assert.equal(seen.has(guest),false,'duplicate runtime destination');seen.add(guest);
   const file=path.join(runtimeBundle,'inputs',input.sha256),st=fs.lstatSync(file);assert.ok(st.isFile()&&st.size>=64&&st.size<=268435456);
   const bytes=fs.readFileSync(file);assert.equal(hash(bytes),'sha256:'+input.sha256);assert.deepEqual([...bytes.subarray(0,6)],[127,69,76,70,2,1]);assert.equal(bytes.readUInt16LE(18),nativeLinuxProfile().machine);
   copy(file,guest.slice(1),0o755);return {path:guest,sha256:input.sha256};
  };
  const executable=materialize(runtime.executable,'/control/engines/'+target),dependencies=[];
  for(const input of runtime.dependencies){assert.match(input.path,/^\/(?:lib|lib64|usr\/lib)\//,'runtime dependency must stay in the fixed library roots');dependencies.push(materialize(input,input.path));}
  const configuration={schema:manifest.schema,platform:manifest.platform,architecture:manifest.architecture,runtimes:{[target]:{...runtime,executable,dependencies}}};
  writeJson(path.join(root,'control/runtimes.json'),configuration);fs.chmodSync(path.join(root,'control/runtimes.json'),0o644);
  result[target]={addressBytes:target==='javascript'?4294967296:17179869184,fileBytes:268435456,manifestSHA256:hash(fs.readFileSync(path.join(root,'control/runtimes.json'))),executable,dependencies,versionStdout:runtime.versionStdout};
 }
 assert.ok(Object.keys(result).length>0);assert.deepEqual(fs.readFileSync(manifestFile),source,'runtime manifest changed while staging');return result;
}
