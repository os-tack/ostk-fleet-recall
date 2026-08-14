import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const page=readFileSync(new URL('../../src/demo.html',import.meta.url),'utf8');

function extractFunction(name){
  const marker=`function ${name}(`;
  const start=page.indexOf(marker);
  assert.notEqual(start,-1,`${name} must remain in the embedded demo script`);
  const bodyStart=page.indexOf('{',start+marker.length);
  let depth=0;
  for(let cursor=bodyStart;cursor<page.length;cursor+=1){
    if(page[cursor]==='{')depth+=1;
    if(page[cursor]==='}'){
      depth-=1;
      if(depth===0)return page.slice(start,cursor+1);
    }
  }
  throw new Error(`${name} has no closing brace`);
}

const context=vm.createContext({Set,String,Number,Array});
vm.runInContext(
  `${extractFunction('isClaimProjection')}\n${extractFunction('uniqueHits')}`,
  context,
);

const hit=(chunk_id,snippet,extra={},source='markdown')=>({
  chunk_id,
  snippet,
  source,
  extra,
});
test('exact supporting source chunks precede synthetic claim projections',()=>{
  const body={
    data:{hits:[
      hit('claim:12','synthetic implementation claim',{claim_id:12},'ostk_memory'),
      hit('unrelated','ordinary semantic result'),
      hit('docs-support','the specification says remember supports retractions'),
      hit('code-support','the implementation only accepts record',{},'code'),
    ]},
    diagnostics:{retrieval:{supporting_chunk_ids:['code-support','docs-support']}},
  };

  assert.deepEqual(
    Array.from(context.uniqueHits(body),candidate=>candidate.chunk_id),
    ['docs-support','code-support','claim:12'],
  );
});

test('unmapped results keep fused rank and diagnostics cannot promote a claim row',()=>{
  const ranked=[
    hit('claim:12','first',{claim_id:12},'ostk_memory'),
    hit('ordinary','second'),
    hit('third','third'),
    hit('fourth','fourth'),
  ];
  assert.deepEqual(
    Array.from(context.uniqueHits({data:{hits:ranked}}),candidate=>candidate.chunk_id),
    ['claim:12','ordinary','third'],
  );
  assert.deepEqual(
    Array.from(context.uniqueHits({
      data:{hits:ranked},
      diagnostics:{retrieval:{supporting_chunk_ids:['claim:12']}},
    }),candidate=>candidate.chunk_id),
    ['claim:12','ordinary','third'],
  );
});
