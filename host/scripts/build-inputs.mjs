import {readFileSync,readdirSync} from 'node:fs';
import {join,relative,sep} from 'node:path';
import {createHash} from 'node:crypto';
export const digest=bytes=>'sha256:'+createHash('sha256').update(bytes).digest('hex');
export function treeHash(base,dirs,files=[]){
  const items=[];
  function visit(dir){for(const e of readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name<b.name?-1:1)){const p=join(dir,e.name);if(e.isDirectory())visit(p);else items.push([relative(base,p).split(sep).join('/'),digest(readFileSync(p))]);}}
  for(const dir of dirs)visit(join(base,dir));for(const file of files)items.push([file,digest(readFileSync(join(base,file)))]);
  return digest(JSON.stringify(items));
}
