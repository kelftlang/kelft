import fs from 'node:fs';import path from 'node:path';import {Readable,Transform} from 'node:stream';import {pipeline} from 'node:stream/promises';
export function diagnostic(value,secrets=[]){let s=String(value);for(const secret of [...secrets,process.env.GH_TOKEN,process.env.GITHUB_TOKEN].filter(Boolean))s=s.split(secret).join('[REDACTED]');return s.replace(/https?:\/\/[^\s"'<>]+/g,value=>{try{const u=new URL(value);return u.origin+u.pathname;}catch{return '[URL]';}}).replace(/\b(?:Bearer|Basic)\s+[^\s"'<>]+/gi,'Authorization [REDACTED]').replace(/\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)/g,'[REDACTED]').slice(0,2048);}
async function responseDiagnostic(response){
 // Capture only a bounded error-body prefix; the request deadline also covers this read.
 const chunks=[];let size=0;try{for await(const chunk of response.body){const bytes=Buffer.from(chunk),take=Math.min(bytes.length,8192-size);chunks.push(bytes.subarray(0,take));size+=take;if(size===8192)break;}}catch{}
 const raw=Buffer.concat(chunks).toString('utf8');let message=raw;
 try{const value=JSON.parse(raw);message=typeof value.message==='string'?value.message:raw;}catch{}
 return message.replace(/[\x00-\x1f\x7f]/g,' ');
}
const transient=error=>['ECONNRESET','ECONNREFUSED','ETIMEDOUT','EAI_AGAIN','UND_ERR_SOCKET','UND_ERR_CONNECT_TIMEOUT','UND_ERR_HEADERS_TIMEOUT','UND_ERR_BODY_TIMEOUT','RELEASE_TIMEOUT'].includes(error.code??error.cause?.code);
export async function request(url,init={},consume=response=>response.json(),{fetcher=fetch,timeout=30000,sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms)),log=message=>console.error(message),operation='release request',secrets=[]}={}){
 const method=init.method??'GET',attempts=method==='GET'?3:1;
 for(let attempt=1;attempt<=attempts;attempt++){
  const start=Date.now(),controller=new AbortController();let timer,response,timedOut=false,delay=attempt*500;
  const timeoutError=Object.assign(Error('request deadline exceeded'),{code:'RELEASE_TIMEOUT'});
  try{
   return await Promise.race([(async()=>{response=await fetcher(url,{...init,signal:controller.signal});if(!response.ok){if(response.status===404&&init.allowMissing)return null;const detail=await responseDiagnostic(response);const e=Object.assign(Error('HTTP '+response.status+(detail?': '+detail:'')),{status:response.status});if([408,429,500,502,503,504].includes(response.status)){e.retryable=true;const retry=response.headers.get('retry-after');if(retry){const ms=/^\d+$/.test(retry)?Number(retry)*1000:Date.parse(retry)-Date.now();if(Number.isFinite(ms))delay=Math.min(5000,Math.max(0,ms));}}if(response.status!==404||!init.allowMissing)throw e;return null;}return await consume(response,controller.signal);})(),new Promise((_,reject)=>{timer=setTimeout(()=>{timedOut=true;controller.abort(timeoutError);reject(timeoutError);},timeout);})]);
  }catch(error){if(timedOut)error=timeoutError;controller.abort();const retryable=error.retryable===true||transient(error);const message=diagnostic(`${operation}: ${method} ${new URL(url).origin}${new URL(url).pathname}; attempt ${attempt}/${attempts}; elapsed ${Date.now()-start}ms; HTTP ${response?.status??'none'}; request-id ${String(response?.headers?.get('x-github-request-id')??'none').replace(/[^A-Za-z0-9:-]/g,'').slice(0,128)}; code ${error.code??error.cause?.code??error.name}; ${error.message}`,secrets);log(message);if(attempt===attempts||!retryable){const failure=Error(message);failure.status=error.status;failure.ambiguous=method!=='GET'&&(retryable||!response||response.ok);throw failure;}
  }finally{clearTimeout(timer);try{await response?.body?.cancel();}catch{}}
  await sleep(delay);
 }
}
export async function boundedText(response,maximum=4*1024*1024){let size=0;const chunks=[];for await(const chunk of response.body){size+=chunk.length;if(size>maximum)throw Error('Response exceeds bound');chunks.push(Buffer.from(chunk));}return Buffer.concat(chunks).toString('utf8');}
export async function downloadFile(url,init,{directory,name='download',size,fetcher=fetch,nameID=()=>crypto.randomUUID(),...settings}){
 if(!Number.isSafeInteger(size)||size<=0||size>2*1024**3)throw Error('Invalid download size');
 return request(url,init,async(response,signal)=>{const suffix=['.json','.jsonl'].includes(path.extname(name))?path.extname(name):'',id=nameID();if(!/^[a-zA-Z0-9-]+$/.test(id))throw Error('Invalid local download identifier');const file=path.join(directory,'download-'+id+suffix);let bytes=0;
  const bound=new Transform({transform(chunk,encoding,done){bytes+=chunk.length;done(bytes>size?Error('Asset exceeds recorded bound'):null,chunk);}});
  const handle=await fs.promises.open(file,'wx');
  try{await pipeline(Readable.fromWeb(response.body),bound,handle.createWriteStream(),{signal});if(bytes!==size)throw Error('Asset truncated');return file;}catch(error){try{fs.unlinkSync(file);}catch{}throw error;}
 },{fetcher,timeout:180000,operation:'asset download',...settings});
}
