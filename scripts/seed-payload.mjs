import fs from 'node:fs';
import path from 'node:path';
import {safeFile,safeName,readJSON,sha256,requireThat,inventory} from './common.mjs';

export function seedPayloadReader(directory,manifest){
  const declared=new Map(),native=manifest.schema==='kelft.native-seed/1';
  requireThat(Array.isArray(manifest.files)&&manifest.files.length>0&&manifest.files.length<=8192,'Invalid seed inventory');
  let total=0;const maximum=manifest.target?.startsWith('macos-')?16*1024*1024*1024:512*1024*1024;
  for(const row of manifest.files){safeName(row.path);const key=row.path.toLowerCase();requireThat(!declared.has(key),'Duplicate seed path');requireThat(Number.isSafeInteger(row.bytes)&&row.bytes>=0&&row.bytes<=256*1024*1024&&/^sha256:[a-f0-9]{64}$/.test(row.sha256),'Invalid seed file');total+=row.bytes;requireThat(total<=maximum,'Seed package bound');if(native)requireThat([0o644,0o755].includes(row.mode),'Invalid seed mode');declared.set(key,row);}
  const virtual=new Map(),physical=new Set(),partsFile=safeFile(directory,'seed-parts.json');
  if(fs.existsSync(partsFile)){
    requireThat(fs.statSync(partsFile).size<=2*1024*1024,'Seed parts manifest bound');const parts=readJSON(partsFile);requireThat(parts.schema==='kelft.seed-parts/1'&&Array.isArray(parts.files)&&parts.files.length<=8192,'Invalid seed parts');
    physical.add('seed-parts.json');
    for(const row of parts.files){safeName(row.path);requireThat(row.path.startsWith('rootfs/')&&declared.has(row.path.toLowerCase())&&!virtual.has(row.path)&&!fs.existsSync(safeFile(directory,row.path)),'Invalid split destination');requireThat(Number.isSafeInteger(row.bytes)&&row.bytes>=0&&row.bytes<=256*1024*1024&&Array.isArray(row.parts)&&row.parts.length>0&&row.parts.length<=256&&[0o644,0o755].includes(row.mode),'Invalid split payload');virtual.set(row.path,row);for(const item of row.parts){safeName(item.path);requireThat(item.path.startsWith('parts/')&&!physical.has(item.path),'Duplicate or invalid seed part');physical.add(item.path);}}
  }
  function read(name){
    const row=declared.get(name.toLowerCase());requireThat(row&&row.path===name,'Undeclared seed payload');let bytes;
    if(virtual.has(name)){
      const spec=virtual.get(name),chunks=[];let total=0;
      for(const part of spec.parts){requireThat(Number.isSafeInteger(part.bytes)&&part.bytes>0&&part.bytes<=48*1024*1024&&/^sha256:[a-f0-9]{64}$/.test(part.sha256),'Invalid seed part');total+=part.bytes;requireThat(total<=spec.bytes,'Seed part size bound');const file=safeFile(directory,part.path),stat=fs.lstatSync(file);requireThat(stat.isFile()&&stat.size===part.bytes,'Changed seed part');const data=fs.readFileSync(file);requireThat(sha256(data)===part.sha256,'Changed seed part');chunks.push(data);}
      requireThat(total===spec.bytes,'Seed part length differs');bytes=Buffer.concat(chunks,total);requireThat(sha256(bytes)===spec.sha256,'Split seed digest differs');
    }else{const file=safeFile(directory,name),stat=fs.lstatSync(file);requireThat(stat.isFile()&&stat.size===row.bytes,'Changed seed input');bytes=fs.readFileSync(file);}
    requireThat(bytes.length===row.bytes&&sha256(bytes)===row.sha256,'Changed seed input: '+name);return bytes;
  }
  for(const row of manifest.files){read(row.path);if(!virtual.has(row.path))physical.add(row.path);}
  const actual=inventory(directory,{exclude:name=>native&&['seed.json','READY','.protocol-checked.json'].includes(name)}).map(row=>row.path).sort();requireThat(JSON.stringify(actual)===JSON.stringify([...physical].sort()),'Uninventoried or missing seed files');
  return {read};
}

export function copySeedInputs(directory,manifest,destination){
  const reader=seedPayloadReader(directory,manifest),modes=new Map();
  if(manifest.files.some(row=>row.path==='runtime-modes.json')){const metadata=JSON.parse(reader.read('runtime-modes.json'));requireThat(metadata.schema==='kelft.runtime-modes/1'&&Array.isArray(metadata.files)&&metadata.files.length<=131072,'Invalid runtime modes');for(const row of metadata.files){safeName(row.path);requireThat(!modes.has(row.path)&&[0o444,0o555,0o600,0o644,0o700,0o755].includes(row.mode),'Invalid runtime mode');modes.set(row.path,row.mode);}}
  for(const row of manifest.files){if(!/^(rootfs\/|notices\/|runtime-modes\.json$)/.test(row.path))continue;const file=safeFile(destination,row.path);fs.mkdirSync(path.dirname(file),{recursive:true});const mode=modes.get(row.path)??(row.mode&0o111?0o755:0o644);fs.writeFileSync(file,reader.read(row.path),{flag:'wx',mode});if(process.platform!=='win32')fs.chmodSync(file,mode);}
}
