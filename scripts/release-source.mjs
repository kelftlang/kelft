import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {spawnSync} from 'node:child_process';
import {requireThat} from './common.mjs';
export const repository='kelftlang/kelft';
export function releaseIdentity(release,changelog){
  const version=release.version;requireThat(typeof version==='string'&&version.length<=128&&/^(0|[1-9][0-9]{0,7})\.(0|[1-9][0-9]{0,7})\.(0|[1-9][0-9]{0,7})(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(version),'Canonical compiler version required');
  for(const part of version.split('+')[0].split('-').slice(1).join('-').split('.'))requireThat(!/^0[0-9]+$/.test(part),'Numeric prerelease identifier has leading zeros');
  const tag='v'+version,sections=[...changelog.matchAll(/^##[ \t]+([^\r\n]+)\r?$/gm)],matches=sections.map((value,index)=>({value,index})).filter(row=>row.value[1].trim()===tag);
  requireThat(matches.length===1,'Exactly one changelog section required for '+tag);const {value,index}=matches[0],notes=changelog.slice(value.index+value[0].length,sections[index+1]?.index??changelog.length).trim();requireThat(notes.length>0,'Empty release changelog');return {version,tag,title:'Kelft '+tag,notes,prerelease:version.split('+')[0].includes('-')};
}
export function githubSignature(commit,candidate){
  const value=commit?.commit?.verification;requireThat(commit?.sha===candidate&&value?.verified===true&&value.reason==='valid','Candidate must have a valid GitHub signature');
  requireThat(commit.committer?.login==='web-flow'&&commit.commit.committer?.email==='noreply@github.com','Candidate must be a GitHub web-flow merge commit');
  requireThat(typeof value.payload==='string'&&value.payload.length>0&&value.signature?.startsWith('-----BEGIN PGP SIGNATURE-----'),'Missing GitHub signature material');return value;
}
export function verifyGitHubKey(verification,keys,{run=spawnSync}={}){
  requireThat(typeof keys==='string'&&keys.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----'),'GitHub signing keys unavailable');const parent=fs.realpathSync(os.tmpdir()),home=fs.mkdtempSync(path.join(parent,'kelft-release-gpg-'));fs.chmodSync(home,0o700);
  const invoke=(args,input)=>{const value=run('gpg',['--no-options','--homedir',home,'--batch','--no-auto-key-retrieve',...args],{input,encoding:'utf8',timeout:120000,maxBuffer:4<<20,windowsHide:true});requireThat(value.status===0&&!value.error&&!value.signal,'GitHub source signature verification failed');return value.stdout;};
  try{invoke(['--import'],keys);fs.writeFileSync(path.join(home,'commit.asc'),verification.signature);fs.writeFileSync(path.join(home,'commit.txt'),verification.payload);const status=invoke(['--status-fd','1','--verify',path.join(home,'commit.asc'),path.join(home,'commit.txt')]);const valid=/^\[GNUPG:\] VALIDSIG ([A-F0-9]{40,64})\b/m.exec(status);requireThat(valid,'Source signature does not match GitHub signing keys');return valid[1];}
  finally{requireThat(path.dirname(home)===parent&&path.basename(home).startsWith('kelft-release-gpg-')&&!fs.lstatSync(home).isSymbolicLink(),'Unsafe signature-check cleanup');fs.rmSync(home,{recursive:true,force:true});}
}
export async function verifyPublicSource(api,candidate,{fetcher=fetch,run=spawnSync}={}){
  requireThat(/^[a-f0-9]{40}$/.test(candidate??''),'Exact public candidate required');const verification=githubSignature(await api('GET','/repos/'+repository+'/commits/'+candidate),candidate),response=await fetcher('https://github.com/web-flow.gpg',{signal:AbortSignal.timeout(30000)});requireThat(response.ok,'Cannot retrieve GitHub signing keys');
  const reader=response.body.getReader(),chunks=[];let size=0;try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;requireThat(size<=1<<20,'GitHub signing key response exceeds bound');chunks.push(Buffer.from(value));}}finally{await reader.cancel();}
  return {status:'passed',candidate,fingerprint:verifyGitHubKey(verification,Buffer.concat(chunks).toString('utf8'),{run})};
}
export async function versionTag(api,tag,candidate,{required=false}={}){
  const ref=await api('GET','/repos/'+repository+'/git/ref/tags/'+encodeURIComponent(tag),undefined,{missing:true});if(!ref){requireThat(!required,'Required version tag missing');return null;}
  requireThat(ref.ref==='refs/tags/'+tag,'Unexpected version tag reference');let object=ref.object;for(let depth=0;object?.type==='tag'&&depth<8;depth++)object=(await api('GET','/repos/'+repository+'/git/tags/'+object.sha)).object;
  requireThat(object?.type==='commit'&&object.sha===candidate,'Version tag identifies a different commit; it will not be moved');return ref;
}
export async function ensureVersionTag(api,tag,candidate){
  if(!await versionTag(api,tag,candidate)){try{await api('POST','/repos/'+repository+'/git/refs',{ref:'refs/tags/'+tag,sha:candidate});}catch(error){if(![409,422].includes(error.status))throw error;}}
  return versionTag(api,tag,candidate,{required:true});
}
export async function releaseContext(api,candidate,version,{publish=false,env=process.env,fetcher=fetch,run=spawnSync}={}){
  const tag='v'+version,ref=await versionTag(api,tag,candidate,{required:publish}),compared=await api('GET','/repos/'+repository+'/compare/'+candidate+'...main'),source=await verifyPublicSource(api,candidate,{fetcher,run});
  return {repository:env.GITHUB_REPOSITORY,ref:env.GITHUB_REF,candidate,workflowCommit:env.GITHUB_SHA,version,tag,tagCommit:ref?candidate:null,onMain:['ahead','identical'].includes(compared.status),sourceVerified:source.status==='passed',source};
}
