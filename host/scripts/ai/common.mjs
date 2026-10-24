import * as fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

export const VERSION = '0.1';
export const repo = path.resolve(import.meta.dirname, '../..');
export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort((a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b))).map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',') + '}';
}
export const hash = value => 'sha256:' + createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : canonical(value)).digest('hex');
export const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));
export function syncFile(file){const fd=fs.openSync(file,'r+');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
export function syncDirectory(directory){if(process.platform==='win32')return;const fd=fs.openSync(directory,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
export function writeImmutable(file,value){fs.mkdirSync(path.dirname(file),{recursive:true});const fd=fs.openSync(file,'wx',0o600);try{fs.writeFileSync(fd,JSON.stringify(value,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}syncDirectory(path.dirname(file));}
export function exclusive(file){fs.mkdirSync(path.dirname(file),{recursive:true});let fd;try{fd=fs.openSync(file,'wx',0o600);}catch{throw new Error('operation is locked; inspect interrupted execution before removing the lock');}fs.writeFileSync(fd,JSON.stringify({pid:process.pid,createdAt:new Date().toISOString()}));return ()=>{fs.closeSync(fd);fs.unlinkSync(file);};}
export function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), {recursive:true});
  const temporary = file + '.' + randomUUID() + '.tmp';
  fs.writeFileSync(temporary, JSON.stringify(value,null,2)+'\n', {flag:'wx',mode:0o600});
  syncFile(temporary);
  fs.renameSync(temporary,file);
  syncDirectory(path.dirname(file));
}
export function inside(root, file) {
  const rel=path.relative(root,file);return rel===''||!path.isAbsolute(rel)&&rel!=='..'&&!rel.startsWith('..'+path.sep);
}
export function relativePath(name) {
  if(typeof name!=='string'||!name||name.length>220||name.includes('\\')||/[\x00-\x1f:<>"|?*]/.test(name)||name.startsWith('/'))throw new Error('unsafe proposal path');
  const parts=name.split('/');
  if(parts.some(p=>!p||p==='.'||p==='..'||/[. ]$/.test(p)||/^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(p)))throw new Error('unsafe proposal path');
  return name;
}
export function safePath(root, name) {
  relativePath(name);root=path.resolve(root);const target=path.resolve(root,name);
  if(!inside(root,target))throw new Error('path escapes workspace');
  // lstat rejects Windows junctions and symbolic links, including ancestor links.
  let current=path.parse(root).root;
  for(const part of path.relative(current,target).split(path.sep)) {
    current=path.join(current,part);
    try {const stat=fs.lstatSync(current);if(stat.isSymbolicLink())throw new Error('symlink or junction is not authorized');
      if(!inside(fs.realpathSync(path.parse(root).root),fs.realpathSync(current)))throw new Error('reparse path escapes root');
    } catch(e) {if(e.code!=='ENOENT')throw e;}
  }
  if(fs.existsSync(root)&&!inside(fs.realpathSync(root),fs.existsSync(target)?fs.realpathSync(target):target))throw new Error('canonical path escapes workspace');
  if(process.platform==='win32'&&fs.existsSync(root)){
    let parent=root;for(const part of name.split('/')){
      if(!fs.existsSync(parent))break;const entries=fs.readdirSync(parent),folded=entries.filter(entry=>entry.toLowerCase()===part.toLowerCase());
      if(folded.length>1||!entries.includes(part)&&(folded.length||fs.existsSync(path.join(parent,part))))throw new Error('Windows path casing or short-name alias collision');
      parent=path.join(parent,part);
    }
  }
  return target;
}
export function fileHash(root,name) {const file=safePath(root,name);return fs.existsSync(file)?hash(fs.readFileSync(file)):null;}
export function snapshot(root,names) {return Object.fromEntries([...new Set(names)].sort().map(name=>[name,fileHash(root,name)]));}
export function treeFiles(root) {
  const result=[];if(!fs.existsSync(root))return result;
  function walk(dir){for(const entry of fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){const full=path.join(dir,entry.name),name=path.relative(root,full).split(path.sep).join('/');safePath(root,name);if(entry.isDirectory())walk(full);else if(entry.isFile())result.push(name);else throw new Error('unsupported filesystem entry');}}
  walk(root);return result;
}
