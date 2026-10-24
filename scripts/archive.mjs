import fs from 'node:fs';
import zlib from 'node:zlib';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {Readable,Transform} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import {requireThat, safeName} from './common.mjs';

const MAX = 512 << 20;
export const SOURCE_ARCHIVE_LIMIT=2*1024*1024*1024;
export function readTar(bytes){
 requireThat(bytes.length<=64*1024*1024,'Corresponding source archive bound');const rows=[],seen=new Set();let at=0;
 while(at+512<=bytes.length){const header=bytes.subarray(at,at+512);if(header.every(value=>value===0))return rows;const text=(offset,length)=>header.subarray(offset,offset+length).toString('utf8').replace(/\0.*$/s,''),number=(offset,length)=>{const raw=text(offset,length).trim();requireThat(/^[0-7]*$/.test(raw),'Unsupported source archive number');return parseInt(raw||'0',8);};requireThat(header.reduce((sum,value,index)=>sum+(index>=148&&index<156?32:value),0)===number(148,8),'Source archive checksum differs');const prefix=text(345,155),name=((prefix?prefix+'/':'')+text(0,100)).replace(/^\.\//,'').replace(/\/$/,''),size=number(124,12),type=header[156];safeName(name);requireThat([0,48,53].includes(type)&&Number.isSafeInteger(size)&&size>=0&&at+512+size<=bytes.length,'Source archive type or size differs');at+=512;if(type!==53){requireThat(!seen.has(name.toLowerCase())&&rows.length<8192,'Duplicate or oversized source inventory');seen.add(name.toLowerCase());rows.push({path:name,data:Buffer.from(bytes.subarray(at,at+size)),mode:number(100,8)&0o111?0o755:0o644});}at+=Math.ceil(size/512)*512;
 }throw Error('Truncated source archive');
}
function tarHeader(row,size){
  safeName(row.path);let name=row.path,prefix='';
  if(Buffer.byteLength(name)>100){const at=name.lastIndexOf('/');prefix=name.slice(0,at);name=name.slice(at+1);}
  requireThat(Buffer.byteLength(name)<=100&&Buffer.byteLength(prefix)<=155,'USTAR name exceeds bound');
  const header=Buffer.alloc(512),oct=(at,length,value)=>header.write(value.toString(8).padStart(length-1,'0')+'\0',at,length,'ascii');
  header.write(name,0,100);header.write(prefix,345,155);oct(100,8,row.mode??0o644);oct(108,8,0);oct(116,8,0);oct(124,12,size);oct(136,12,0);
  header.fill(32,148,156);header[156]=48;header.write('ustar\0',257,6);header.write('00',263,2);header.write(header.reduce((n,b)=>n+b,0).toString(8).padStart(6,'0')+'\0 ',148,8);return header;
}
// Source archives have a distinct aggregate bound; native package limits remain fixed.
export async function writeSourceArchive(rows,output){
  requireThat(rows.length>0&&rows.length<=8192,'Source archive entry bound');
  const seen=new Set(),prepared=[];let total=1024;
  for(const row of rows){safeName(row.path);requireThat(!seen.has(row.path.toLowerCase()),'Archive path collision');seen.add(row.path.toLowerCase());
    const stat=row.data?null:fs.lstatSync(row.file),size=row.data?.length??stat.size;
    requireThat(!stat||stat.isFile()&&!stat.isSymbolicLink(),'Archive regular file required');requireThat(Number.isSafeInteger(size)&&size>=0&&size<=256*1024*1024,'Archive member exceeds bound');
    total+=512+Math.ceil(size/512)*512;requireThat(total<=SOURCE_ARCHIVE_LIMIT,'Source archive exceeds bound');prepared.push({...row,size,header:tarHeader(row,size)});
  }
  requireThat(!fs.existsSync(output),'Archive output exists');const temporary=path.join(path.dirname(output),'.'+path.basename(output)+'.partial-'+randomBytes(12).toString('hex'));
  async function* contents(){for(const row of prepared){yield row.header;let count=0;const hash=createHash('sha256');
      for await(const bytes of row.data?[row.data]:fs.createReadStream(row.file)){count+=bytes.length;requireThat(count<=row.size,'Archive input grew');hash.update(bytes);yield bytes;}
      requireThat(count===row.size,'Archive input size changed');if(row.sha256)requireThat('sha256:'+hash.digest('hex')===row.sha256,'Archive input digest changed');
      const padding=(512-row.size%512)%512;if(padding)yield Buffer.alloc(padding);
    }yield Buffer.alloc(1024);}
  const digest=createHash('sha256');let bytes=0,header=Buffer.alloc(0),started=false;
  const canonical=new Transform({transform(chunk,encoding,callback){try{if(!started){header=Buffer.concat([header,chunk]);if(header.length<10){callback();return;}header[9]=255;chunk=header;started=true;}bytes+=chunk.length;digest.update(chunk);callback(null,chunk);}catch(error){callback(error);}}});
  try{await pipeline(Readable.from(contents()),zlib.createGzip({level:9}),canonical,fs.createWriteStream(temporary,{flags:'wx',mode:0o644}));requireThat(!fs.existsSync(output),'Archive output appeared');fs.renameSync(temporary,output);return {file:path.basename(output),bytes,sha256:'sha256:'+digest.digest('hex'),uncompressedBytes:total};}
  catch(error){if(fs.existsSync(temporary))fs.unlinkSync(temporary);throw error;}
}
function data(row) {
  const bytes = row.data ?? fs.readFileSync(row.file);
  requireThat(bytes.length <= 256 << 20, 'Archive member exceeds bound'); return bytes;
}
export function tarGzip(rows) {
  const chunks = []; let total = 1024;
  for (const row of rows) {
    safeName(row.path); const bytes = data(row), header = Buffer.alloc(512);
    let name = row.path, prefix = '';
    if (Buffer.byteLength(name) > 100) { const at = name.lastIndexOf('/'); prefix = name.slice(0, at); name = name.slice(at + 1); }
    requireThat(Buffer.byteLength(name) <= 100 && Buffer.byteLength(prefix) <= 155, 'USTAR name exceeds bound');
    header.write(name, 0, 100); header.write(prefix, 345, 155);
    const oct = (at, length, value) => header.write(value.toString(8).padStart(length - 1, '0') + '\0', at, length, 'ascii');
    oct(100, 8, row.mode ?? 0o644); oct(108, 8, 0); oct(116, 8, 0); oct(124, 12, bytes.length); oct(136, 12, 0);
    header.fill(32, 148, 156); header[156] = 48; header.write('ustar\0', 257, 6); header.write('00', 263, 2);
    header.write(header.reduce((a,b) => a+b, 0).toString(8).padStart(6, '0') + '\0 ', 148, 8);
    const padding = (512 - bytes.length % 512) % 512; total += 512 + bytes.length + padding;
    requireThat(total <= MAX, 'Archive exceeds bound'); chunks.push(header, bytes, Buffer.alloc(padding));
  }
  chunks.push(Buffer.alloc(1024)); const result = zlib.gzipSync(Buffer.concat(chunks), {level: 9, mtime: 0}); result[9] = 255; return result;
}
const crcTable = Array.from({length: 256}, (_, n) => { for (let i = 0; i < 8; i++) n = n & 1 ? 0xedb88320 ^ n >>> 1 : n >>> 1; return n >>> 0; });
function crc32(bytes) { let crc = 0xffffffff; for (const n of bytes) crc = crcTable[(crc ^ n) & 255] ^ crc >>> 8; return (crc ^ 0xffffffff) >>> 0; }
export function zip(rows) {
  requireThat(rows.length <= 8192, 'ZIP entry bound'); const parts = [], directory = []; let offset = 0;
  for (const row of rows) {
    safeName(row.path); const name = Buffer.from(row.path), bytes = data(row), compressed = zlib.deflateRawSync(bytes, {level: 9}), crc = crc32(bytes);
    const local = Buffer.alloc(30); local.writeUInt32LE(0x04034b50); local.writeUInt16LE(20, 4); local.writeUInt16LE(0x800, 6); local.writeUInt16LE(8, 8); local.writeUInt16LE(33, 12);
    local.writeUInt32LE(crc, 14); local.writeUInt32LE(compressed.length, 18); local.writeUInt32LE(bytes.length, 22); local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46); central.writeUInt32LE(0x02014b50); central.writeUInt16LE(0x314, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(0x800, 8); central.writeUInt16LE(8, 10); central.writeUInt16LE(33, 14);
    central.writeUInt32LE(crc, 16); central.writeUInt32LE(compressed.length, 20); central.writeUInt32LE(bytes.length, 24); central.writeUInt16LE(name.length, 28); central.writeUInt32LE(((0o100000 | (row.mode ?? 0o644)) << 16) >>> 0, 38); central.writeUInt32LE(offset, 42);
    parts.push(local, name, compressed); directory.push(central, name); offset += local.length + name.length + compressed.length; requireThat(offset <= MAX, 'ZIP exceeds bound');
  }
  const index = Buffer.concat(directory), end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50); end.writeUInt16LE(rows.length, 8); end.writeUInt16LE(rows.length, 10); end.writeUInt32LE(index.length, 12); end.writeUInt32LE(offset, 16);
  requireThat(offset + index.length + 22 <= MAX, 'ZIP exceeds bound'); return Buffer.concat([...parts, index, end]);
}
