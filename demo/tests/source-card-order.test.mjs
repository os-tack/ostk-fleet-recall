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

const context=vm.createContext({Set,String,Number,Array,Map,JSON,Date});
vm.runInContext(
  [
    'hitClaimId',
    'uniqueHits',
    'conflictMatch',
    'chooseConflict',
  ].map(extractFunction).join('\n'),
  context,
);

const hit=(chunk_id,snippet,extra={},source='markdown')=>({
  chunk_id,
  snippet,
  source,
  extra,
});
test('support diagnostics never reorder the fused evidence',()=>{
  const body={
    data:{hits:[
      hit('purpose','Fleet Recall exists because agent workers are replaceable'),
      hit('docs-support','the specification says remember supports retractions'),
      hit('code-support','the implementation only accepts record',{},'code'),
      hit('claim:12','synthetic implementation claim',{claim_id:12},'ostk_memory'),
    ]},
    diagnostics:{retrieval:{supporting_chunk_ids:['code-support','docs-support']}},
  };

  assert.deepEqual(
    Array.from(context.uniqueHits(body),candidate=>candidate.chunk_id),
    ['purpose','docs-support','code-support'],
  );
});

test('a selected conflict removes only its duplicate claim cards',()=>{
  const ranked=[
    hit('claim:12','first',{claim_id:12},'ostk_memory'),
    hit('ordinary','second'),
    hit('claim:13','third',{claim_id:13},'ostk_memory'),
    hit('fourth','fourth'),
    hit('fifth','fifth'),
  ];
  assert.deepEqual(
    Array.from(context.uniqueHits({data:{hits:ranked}}),candidate=>candidate.chunk_id),
    ['claim:12','ordinary','claim:13'],
  );
  assert.deepEqual(
    Array.from(context.uniqueHits({
      data:{hits:ranked},
    },{members:[{id:12},{id:13}]}),candidate=>candidate.chunk_id),
    ['ordinary','fourth','fifth'],
  );
});

const conflict=(id,key,members,detected_at)=>({
  id,
  claim_key:key,
  state:'open',
  members,
  members_truncated:false,
  member_values_elided:false,
  detected_at,
});

test('conflict selection follows exact top-ranked trigger mapping',()=>{
  const migration=conflict(5,'run::migration-strategy',[
    {id:7,actor:'agent-a',subject:'migration',predicate:'strategy',text:'use one dedicated migrator'},
    {id:17,actor:'agent-c',subject:'migration',predicate:'strategy',text:'every worker migrates'},
  ],'2026-08-14T01:00:00Z');
  const retractions=conflict(3,'audit::mcp-remember-supports-deliberate-retractions',[
    {id:9,actor:'agent-a',subject:'mcp remember',predicate:'supports deliberate retractions',text:'the docs say true'},
    {id:10,actor:'agent-c',subject:'mcp remember',predicate:'supports deliberate retractions',text:'the code says false'},
  ],'2026-08-14T02:00:00Z');
  const body={
    data:{hits:[
      hit('claim:7','one dedicated migrator',{claim_id:7},'ostk_memory'),
      hit('code-support','record only',{},'code'),
    ]},
    conflicts:[retractions,migration],
    diagnostics:{retrieval:{conflict_matches:[
      {conflict_id:3,best_fused_hit_rank:2,direct_claim_ids:[],source_support:[{claim_id:10,chunk_id:'code-support',fused_hit_rank:2}]},
      {conflict_id:5,best_fused_hit_rank:1,direct_claim_ids:[7],source_support:[]},
    ]}},
  };

  assert.equal(context.chooseConflict(body).id,5);
  assert.equal(context.chooseConflict({
    data:{hits:[hit('purpose','Fleet Recall exists because workers are replaceable')]},
    conflicts:[retractions],
    diagnostics:{retrieval:{conflict_matches:[{
      conflict_id:3,
      best_fused_hit_rank:4,
      direct_claim_ids:[],
      source_support:[{claim_id:10,chunk_id:'weak-code-tail',fused_hit_rank:4}],
    }]}},
  }),null);
  assert.equal(context.chooseConflict({
    data:{hits:[hit('source-support','the implementation accepts record only',{},'code')]},
    conflicts:[retractions],
    diagnostics:{retrieval:{conflict_matches:[{
      conflict_id:3,
      best_fused_hit_rank:1,
      direct_claim_ids:[],
      source_support:[{claim_id:10,chunk_id:'source-support',fused_hit_rank:1}],
    }]}},
  }).id,3);
  assert.equal(context.chooseConflict({
    data:{hits:[hit('unrelated','a normal ranked result')]},
    conflicts:[retractions],
    diagnostics:{retrieval:{conflict_matches:[{
      conflict_id:3,
      best_fused_hit_rank:1,
      direct_claim_ids:[],
      source_support:[],
    }]}},
  }),null);
});

test('sample selection tracks exact questions and clears for custom input',()=>{
  const buttons=['first question','second question'].map(query=>({
    dataset:{q:query},
    pressed:null,
    setAttribute(name,value){assert.equal(name,'aria-pressed');this.pressed=value;},
  }));
  const selectionContext=vm.createContext({String,sampleButtons:buttons});
  vm.runInContext(extractFunction('syncSampleSelection'),selectionContext);
  selectionContext.syncSampleSelection('second question');
  assert.deepEqual(buttons.map(button=>button.pressed),['false','true']);
  selectionContext.syncSampleSelection('custom question');
  assert.deepEqual(buttons.map(button=>button.pressed),['false','false']);
});

test('presentation language stays tied to exact evidence',()=>{
  assert.match(page,/Evidence ranked for this question/);
  assert.match(page,/fusedRank===1\?'Best match':'Related evidence'/);
  assert.match(page,/operator review required/);
  assert.match(page,/replacement-devpost-final6-20260814T143523Z[.]json/);
  assert.match(page,/setAttribute\('role','alert'\)/);
  assert.doesNotMatch(page,/Sources behind this disagreement/);
  assert.doesNotMatch(page,/hasMatchingEscalation/);
  assert.doesNotMatch(page,/escalated for operator review/);
});
