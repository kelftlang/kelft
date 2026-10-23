import fs from 'node:fs';
import assert from 'node:assert/strict';
import {hash} from './ai/common.mjs';

const bytes=fs.readFileSync(new URL('../native/resource-contracts.json',import.meta.url));
const registry=JSON.parse(bytes);
assert.equal(registry.schema,'kelft-native-resource-registry/2');
// Return a fresh value so a collector cannot modify later selections.
export function nativeResourceContract(target,role){
  assert.ok(Object.hasOwn(registry.profiles,target),'unreviewed native resource target');
  assert.ok(registry.roles.includes(role),'unreviewed native resource role; optional engines require separate contracts');
  return structuredClone({schema:'kelft-native-resource-contract/2',registrySHA256:hash(bytes),target,role,memory:registry.profiles[target],initialStackBytes:registry.initialStackBytes,compiler:registry.compiler});
}
