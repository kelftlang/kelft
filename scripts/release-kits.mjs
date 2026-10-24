import fs from 'node:fs';import path from 'node:path';
import {json,readJSON,requireThat,safeFile} from './common.mjs';
import {snapshot} from './release-contracts.mjs';
import {authenticateRemoteArtifact} from './release-artifact.mjs';
import {validateReuseInputs} from './release-reuse.mjs';
import {generation} from './release-generation.mjs';
import {githubSignature} from './release-source.mjs';
export function validateKit(input,directory,target,current){
  const report=readJSON(safeFile(input,'qualification.json')),inputs=readJSON(safeFile(input,'inputs.json'));requireThat(report.target===target,'Retained target differs');
  validateReuseInputs(report,inputs,current,readJSON(path.join(directory,'.publication.json')).files);
  for(const item of report.generations.slice(1))requireThat(JSON.stringify(generation(safeFile(input,item.name),item.name,item.name==='S3'))===JSON.stringify(item),'Kit generation bytes differ');return report;
}
export async function discoverKits({repository,workflow,branch,target,key,token,fetcher=fetch}){
  requireThat(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository??'')&&/^\.github\/workflows\/[A-Za-z0-9_.-]+\.yml$/.test(workflow??''),'Invalid kit producer');requireThat(/^[a-f0-9]{64}$/.test(key),'Exact generation key required');
  const base='https://api.github.com/repos/'+repository,headers={Authorization:'Bearer '+token,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'},results=[];
  const get=async route=>{const response=await fetcher(base+route,{headers});requireThat(response.ok,'Kit lookup failed: '+response.status);return response.json();};
  for(let page=1;page<=5;page++){
    const listing=await get('/actions/workflows/'+encodeURIComponent(path.basename(workflow))+'/runs?branch='+encodeURIComponent(branch)+'&event=workflow_dispatch&status=completed&per_page=20&page='+page);requireThat(Array.isArray(listing.workflow_runs)&&listing.workflow_runs.length<=20,'Invalid kit run listing');
    for(const run of listing.workflow_runs){if(run.path!==workflow||run.head_branch!==branch||run.event!=='workflow_dispatch'||run.head_repository?.full_name!==repository||run.status!=='completed')continue;
      for(let part=1;part<=5;part++){const assets=await get('/actions/runs/'+run.id+'/artifacts?per_page=100&page='+part);requireThat(Array.isArray(assets.artifacts)&&assets.artifacts.length<=100,'Invalid kit artifact listing');
        for(const artifact of assets.artifacts)if(!artifact.expired&&new RegExp('^kit-'+target+'-'+key+'-attempt-[1-9][0-9]*$').test(artifact.name)&&artifact.workflow_run?.id===run.id&&artifact.workflow_run.head_sha===run.head_sha)results.push({runID:run.id,artifactID:artifact.id,name:artifact.name,commit:run.head_sha});
        if(assets.artifacts.length<100)break;
      }
      if(results.length)return results;
    }
    if(listing.workflow_runs.length<20)break;
  }return results;
}
export async function recoverKit({directory,cache,target,publicCommit,repository,workflow,branch,token,fetcher=fetch}){
  const current=snapshot(directory,{publicCommit}),key=current.components[target].generation.slice(7),misses=[];
  const candidates=await discoverKits({repository,workflow,branch,target,key,token,fetcher});
  for(const candidate of candidates){try{
    const input=path.join(cache,'artifact-'+candidate.artifactID);fs.mkdirSync(input,{recursive:true});
    const transport=await authenticateRemoteArtifact({directory:input,target,...candidate,token,repository,workflow,branch,expectedCommit:candidate.commit,completed:true,fetcher,kitKey:key,materialize:true});
    const report=validateKit(input,directory,target,current);requireThat(report.snapshot.components?.[target]?.generation===current.components[target].generation,'Kit input key differs');
    if(repository==='kelftlang/kelft'){const response=await fetcher('https://api.github.com/repos/'+repository+'/commits/'+candidate.commit,{headers:{Authorization:'Bearer '+token,Accept:'application/vnd.github+json'}});requireThat(response.ok,'Kit source lookup failed');githubSignature(await response.json(),candidate.commit);}
    return {input,transport,misses};
  }catch(error){misses.push({artifact:candidate.artifactID,reason:String(error.message).slice(0,1000)});}}
  return {input:null,misses};
}
