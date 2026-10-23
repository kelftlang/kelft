// Native-host identity for installed Linux packages; no emulation fallback.
import fs from 'node:fs';
import os from 'node:os';
import assert from 'node:assert/strict';
export function nativeLinuxProfile(){
 assert.equal(process.platform,'linux');assert.ok(['x64','arm64'].includes(process.arch));
 const architecture=process.arch==='arm64'?'arm64':'x86_64',machine=architecture==='arm64'?183:62;
 assert.equal(os.machine(),architecture==='arm64'?'aarch64':'x86_64');
 const descriptor=fs.openSync('/proc/self/exe','r'),header=Buffer.alloc(20);
 try{assert.equal(fs.readSync(descriptor,header,0,header.length,0),header.length);}finally{fs.closeSync(descriptor);}
 assert.deepEqual([...header.subarray(0,6)],[127,69,76,70,2,1]);
 assert.equal(header.readUInt16LE(18),machine);
 return {architecture,machine,profile:'linux-'+architecture,target:'native-linux-'+architecture+'-v1',runtimeProfile:'linux-'+architecture+'-development-v1',
  standaloneDirectory:architecture==='arm64'?'native-arm-standalone-package':'native-standalone-package',
  installedDirectory:architecture==='arm64'?'native-arm-installed-package':'native-installed-package',
  profilesDirectory:architecture==='arm64'?'native-arm-installed-profiles':'native-installed-profiles'};
}
