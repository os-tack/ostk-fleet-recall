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
    'hitText',
    'uniqueHits',
    'hitCategory',
    'normalizedEvidenceCategory',
    'filterHits',
    'conflictMatch',
    'chooseConflict',
  ].map(extractFunction).join('\n'),
  context,
);

const plain=value=>JSON.parse(JSON.stringify(value));

const markdownContext=vm.createContext({String,URL,encodeURIComponent});
vm.runInContext(
  [
    'repositoryPathAllowed',
    'repositorySourceContext',
    'safeMarkdownHref',
    'appendMarkdownText',
    'inlineMarkdownTokens',
  ].map(extractFunction).join('\n'),
  markdownContext,
);

class FakeNode {
  constructor(tagName,textContent=''){
    this.tagName=tagName;
    this.textContent=textContent;
    this.children=[];
    this.className='';
    this.attributes={};
    this.listeners={};
    this.hidden=false;
    this.id='';
  }
  append(...children){this.children.push(...children);}
  replaceChildren(...children){this.children=[...children];}
  setAttribute(name,value){this.attributes[name]=String(value);}
  getAttribute(name){return this.attributes[name]??null;}
  addEventListener(name,listener){this.listeners[name]=listener;}
  click(){this.listeners.click?.();}
}

const fakeDocument={
  createElement:tag=>new FakeNode(String(tag).toUpperCase()),
  createTextNode:value=>new FakeNode(null,String(value)),
};
const markdownDomContext=vm.createContext({String,URL,encodeURIComponent,document:fakeDocument});
vm.runInContext(
  [
    'element',
    'repositoryPathAllowed',
    'repositorySourceContext',
    'safeMarkdownHref',
    'appendMarkdownText',
    'inlineMarkdownTokens',
    'renderInlineMarkdown',
  ].map(extractFunction).join('\n'),
  markdownDomContext,
);

function descendantTags(node){
  return [node.tagName,...node.children.flatMap(descendantTags)].filter(Boolean);
}

function descendants(node){
  return [node,...node.children.flatMap(descendants)];
}

function nodeText(node){
  return `${node.textContent||''}${node.children.map(nodeText).join('')}`;
}

const coordinateContext=vm.createContext({String,Number,encodeURIComponent});
vm.runInContext(
  [
    'hitClaimId',
    'repositoryPathAllowed',
    'repositorySourceContext',
    'hitCoordinate',
  ].map(extractFunction).join('\n'),
  coordinateContext,
);

const hit=(chunk_id,snippet,extra={},source='markdown')=>({
  chunk_id,
  snippet,
  source,
  extra,
});

test('bounded inline markdown recognizes only the supported safe subset',()=>{
  const tokens=plain(markdownContext.inlineMarkdownTokens(
    'Use **strong**, *emphasis*, `inline code`, and [the docs](https://example.com/docs).',
  ));
  assert.deepEqual(tokens,[
    {type:'text',value:'Use '},
    {type:'strong',value:'strong'},
    {type:'text',value:', '},
    {type:'emphasis',value:'emphasis'},
    {type:'text',value:', '},
    {type:'code',value:'inline code'},
    {type:'text',value:', and '},
    {type:'link',value:'the docs',href:'https://example.com/docs'},
    {type:'text',value:'.'},
  ]);
});

test('untrusted markdown HTML, images, and non-HTTPS links stay literal text',()=>{
  const unsafe='<script>alert(1)</script> <img src=x onerror=alert(2)> '
    +'![tracking](https://example.com/pixel.png) [bad](javascript:alert(3)) '
    +'[also bad](data:text/html,boom)';
  const tokens=plain(markdownContext.inlineMarkdownTokens(unsafe));
  assert.deepEqual(tokens,[{type:'text',value:unsafe}]);
  assert.equal(markdownContext.safeMarkdownHref('http://example.com/docs'),null);
  assert.equal(markdownContext.safeMarkdownHref('https:example.com/docs'),null);
  assert.equal(markdownContext.safeMarkdownHref('https:\\example.com/docs'),null);
  assert.equal(markdownContext.safeMarkdownHref('https://exam\nple.com/docs'),null);
  assert.equal(markdownContext.safeMarkdownHref('https://user@example.com/docs'),null);
  assert.equal(markdownContext.safeMarkdownHref('not a URL'),null);

  const rendered=markdownDomContext.renderInlineMarkdown(unsafe);
  assert.deepEqual(descendantTags(rendered),['P']);
  assert.equal(rendered.children.map(child=>child.textContent).join(''),unsafe);
});

test('safe inline markdown emits only the allowlisted DOM elements',()=>{
  const rendered=markdownDomContext.renderInlineMarkdown(
    '**strong** *emphasis* `code` [docs](https://example.com/docs)',
  );
  assert.deepEqual(descendantTags(rendered),['P','STRONG','EM','CODE','A']);
  const link=rendered.children.find(child=>child.tagName==='A');
  assert.equal(link.href,'https://example.com/docs');
  assert.equal(link.target,'_blank');
  assert.equal(link.rel,'noopener noreferrer nofollow');
});

test('HTTPS autolinks and immutable repository-relative links render safely',()=>{
  const revision='b'.repeat(40);
  const source={
    source_id:'docs/VIDEO_DEMO.md',
    extra:{source_revision:revision},
  };
  const tokens=plain(markdownContext.inlineMarkdownTokens(
    'See [ARCHITECTURE.md](ARCHITECTURE.md) and <https://example.com/docs>.',
    source,
  ));
  assert.deepEqual(tokens,[
    {type:'text',value:'See '},
    {
      type:'link',
      value:'ARCHITECTURE.md',
      href:`https://github.com/os-tack/ostk-fleet-recall/blob/${revision}/docs/ARCHITECTURE.md`,
    },
    {type:'text',value:' and '},
    {type:'link',value:'https://example.com/docs',href:'https://example.com/docs'},
    {type:'text',value:'.'},
  ]);

  const rendered=markdownDomContext.renderInlineMarkdown(
    '[ARCHITECTURE.md](ARCHITECTURE.md) <https://example.com/docs>',
    source,
  );
  assert.deepEqual(descendantTags(rendered),['P','A','A']);
  assert.ok(rendered.children[0].href.includes(`/blob/${revision}/docs/ARCHITECTURE.md`));
});

test('a wholly inline-code repository link label renders without backticks',()=>{
  const revision='d'.repeat(40);
  const source={source_id:'docs/VIDEO_DEMO.md',extra:{source_revision:revision}};
  const rendered=markdownDomContext.renderInlineMarkdown(
    '[`ARCHITECTURE.md`](ARCHITECTURE.md)',
    source,
  );
  assert.deepEqual(descendantTags(rendered),['P','A','CODE']);
  const link=rendered.children[0];
  assert.equal(link.textContent,'');
  assert.equal(link.children[0].textContent,'ARCHITECTURE.md');
  assert.ok(link.href.includes(`/blob/${revision}/docs/ARCHITECTURE.md`));

  for(const label of ['before `code`','``code``','`unbalanced']){
    const literal=markdownDomContext.renderInlineMarkdown(
      `[${label}](ARCHITECTURE.md)`,
      source,
    );
    assert.deepEqual(descendantTags(literal),['P','A']);
    assert.equal(literal.children[0].textContent,label);
    assert.deepEqual(literal.children[0].children,[]);
  }
});

test('repository-relative links fail closed on unsafe context or destination',()=>{
  const revision='c'.repeat(40);
  const source={source_id:'docs/VIDEO_DEMO.md',extra:{source_revision:revision}};
  const unsafe='[up](../README.md) [root](/README.md) [network](//evil.example/x) '
    +'[encoded](%2e%2e/README.md) [query](ARCHITECTURE.md?raw=1) '
    +'[scheme](javascript:alert(1)) [credentials](https://user@example.com/x)';
  assert.deepEqual(
    plain(markdownContext.inlineMarkdownTokens(unsafe,source)),
    [{type:'text',value:unsafe}],
  );

  for(const unsafeSource of [
    {source_id:'docs/VIDEO_DEMO.md',extra:{source_revision:'0'.repeat(40)}},
    {source_id:'docs/../VIDEO_DEMO.md',extra:{source_revision:revision}},
    {source_id:'conversation/not-a-repository-path',extra:{source_revision:revision}},
  ]){
    const markdown='[ARCHITECTURE.md](ARCHITECTURE.md)';
    assert.deepEqual(
      plain(markdownContext.inlineMarkdownTokens(markdown,unsafeSource)),
      [{type:'text',value:markdown}],
    );
  }

  const nonHttps='<http://example.com> <javascript:alert(1)> <data:text/html,boom>';
  assert.deepEqual(
    plain(markdownContext.inlineMarkdownTokens(nonHttps,source)),
    [{type:'text',value:nonHttps}],
  );
});

test('malformed inline markdown remains literal and rendering input stays bounded',()=>{
  const malformed='open **strong and *emphasis and `code and [link](not-a-url)';
  const tokens=plain(markdownContext.inlineMarkdownTokens(malformed));
  assert.deepEqual(tokens,[{type:'text',value:malformed}]);
  const bounded=plain(markdownContext.inlineMarkdownTokens('x'.repeat(2100)));
  assert.equal(bounded.length,1);
  assert.equal([...bounded[0].value].length,2001);
  assert.ok(bounded[0].value.endsWith('…'));
});

test('source coordinates use immutable revisions only with bounded exact lines',()=>{
  const revision='a'.repeat(40);
  const exact=plain(coordinateContext.hitCoordinate({
    source_id:'docs/PROJECT_PRIMER.md',
    extra:{source_revision:revision,source_line_start:12,source_line_end:20},
  }));
  assert.deepEqual(exact,{
    label:'docs/PROJECT_PRIMER.md:L12-L20',
    href:`https://github.com/os-tack/ostk-fleet-recall/blob/${revision}/docs/PROJECT_PRIMER.md#L12-L20`,
  });

  const single=plain(coordinateContext.hitCoordinate({
    source_id:'src/application.rs',
    extra:{source_revision:revision,source_line_start:79,source_line_end:79},
  }));
  assert.equal(single.label,'src/application.rs:L79');
  assert.ok(single.href.endsWith('/src/application.rs#L79'));

  for(const extra of [
    {source_revision:'0'.repeat(40),source_line_start:12,source_line_end:20},
    {source_revision:revision.toUpperCase(),source_line_start:12,source_line_end:20},
    {source_revision:revision,source_line_start:0,source_line_end:20},
    {source_revision:revision,source_line_start:20,source_line_end:12},
    {source_revision:revision,source_line_start:1,source_line_end:10_002},
    {source_revision:revision,source_line_start:999_999,source_line_end:1_000_001},
  ]){
    const fallback=plain(coordinateContext.hitCoordinate({source_id:'docs/PROJECT_PRIMER.md',extra}));
    assert.deepEqual(fallback,{
      label:'docs/PROJECT_PRIMER.md',
      href:'https://github.com/os-tack/ostk-fleet-recall/blob/main/docs/PROJECT_PRIMER.md',
    });
  }
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
    ['purpose','docs-support','code-support','claim:12'],
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
    ['claim:12','ordinary','claim:13','fourth','fifth'],
  );
  assert.deepEqual(
    Array.from(context.uniqueHits({
      data:{hits:ranked},
    },{members:[{id:12},{id:13}]}),candidate=>candidate.chunk_id),
    ['ordinary','fourth','fifth'],
  );
});

test('source categories preserve fused order and recognize compact claim hits',()=>{
  const compactClaim={
    claim:{id:42,text:'Use one migration owner.'},
    matched_passage:'Use one migration owner.\nkind: decision',
  };
  const ranked=[
    hit('doc-1','first document'),
    hit('code-1','first code',{},'code'),
    compactClaim,
    hit('conversation-1','other memory',{},'conversation'),
    hit('doc-2','second document'),
  ];

  assert.equal(context.hitCategory(ranked[0]),'document');
  assert.equal(context.hitCategory(ranked[1]),'code');
  assert.equal(context.hitCategory(compactClaim),'claim');
  assert.equal(context.hitCategory(ranked[3]),'other');
  assert.equal(context.hitText(compactClaim),'Use one migration owner.');
  assert.equal(context.normalizedEvidenceCategory('CODE'),'code');
  assert.equal(context.normalizedEvidenceCategory('unknown'),'all');
  assert.deepEqual(
    Array.from(context.filterHits(ranked,'document'),candidate=>candidate.chunk_id),
    ['doc-1','doc-2'],
  );
  assert.deepEqual(
    Array.from(context.filterHits(ranked,'all'),candidate=>context.hitText(candidate)),
    ['first document','first code','Use one migration owner.','other memory','second document'],
  );
  assert.deepEqual(Array.from(context.filterHits(null,'code')),[]);
});

const evidenceDomContext=vm.createContext({
  String,Number,Array,Set,Date,Intl,URL,encodeURIComponent,document:fakeDocument,
});
vm.runInContext(
  [
    'element',
    'readable',
    'boundedText',
    'sourceLabel',
    'repositoryPathAllowed',
    'repositorySourceContext',
    'hitCoordinate',
    'safeMarkdownHref',
    'appendMarkdownText',
    'inlineMarkdownTokens',
    'renderInlineMarkdown',
    'shortDate',
    'hitClaimId',
    'hitText',
    'hitCategory',
    'normalizedEvidenceCategory',
    'filterHits',
    'cleanSnippet',
    'renderHitCard',
    'renderEvidenceResults',
  ].map(extractFunction).join('\n'),
  evidenceDomContext,
);

test('evidence controls reveal every returned hit without losing fused rank',()=>{
  const ranked=[
    hit('doc-1','first document'),
    hit('code-1','first code',{},'code'),
    {claim:{id:42,text:'first claim'}},
    hit('doc-2','second document'),
    hit('code-2','second code',{},'code'),
    hit('doc-3','third document'),
    hit('conversation-1','other memory',{},'conversation'),
  ];
  const selections=[];
  const section=evidenceDomContext.renderEvidenceResults(
    ranked,
    ranked,
    'all',
    category=>selections.push(category),
  );
  const nodes=descendants(section);
  const filters=nodes.find(node=>node.className==='evidence-filters');
  const list=nodes.find(node=>node.className==='hit-list');
  const toggle=nodes.find(node=>node.tagName==='BUTTON'&&node.getAttribute('aria-controls')==='evidence-hit-list');
  const filterButtons=filters.children;
  const status=nodes.find(node=>node.getAttribute?.('role')==='status');

  assert.equal(section.getAttribute('aria-labelledby'),'evidence-heading');
  assert.equal(filters.getAttribute('role'),'group');
  assert.equal(filters.getAttribute('aria-label'),'Filter evidence by source type');
  assert.deepEqual(filterButtons.map(node=>node.textContent),['All','Documents','Code','Claims']);
  assert.deepEqual(filterButtons.map(node=>node.getAttribute('aria-pressed')),['true','false','false','false']);
  assert.equal(status.getAttribute('aria-live'),'polite');
  assert.equal(status.textContent,'Showing 3 of 7 returned unique results');
  assert.equal(list.children.length,3);
  assert.equal(toggle.textContent,'Show 4 more results');
  assert.equal(toggle.getAttribute('aria-expanded'),'false');
  assert.equal(toggle.getAttribute('aria-controls'),list.id);

  toggle.click();
  assert.equal(list.children.length,7);
  assert.equal(toggle.textContent,'Show fewer');
  assert.equal(toggle.getAttribute('aria-expanded'),'true');
  assert.match(nodeText(list.children[4]),/Fused rank 5/);

  filterButtons[2].click();
  assert.deepEqual(selections,['code']);
  filterButtons[0].click();
  assert.deepEqual(selections,['code']);
});

test('a backend-filtered response exposes the selected source and truthful count',()=>{
  const codeHits=[
    hit('code-4','fourth-ranked response hit',{},'code'),
    hit('code-9','ninth-ranked response hit',{},'code'),
  ];
  const section=evidenceDomContext.renderEvidenceResults(codeHits,codeHits,'code');
  const nodes=descendants(section);
  const filters=nodes.find(node=>node.className==='evidence-filters');
  const list=nodes.find(node=>node.className==='hit-list');
  const status=nodes.find(node=>node.getAttribute?.('role')==='status');
  const toggle=nodes.find(node=>node.tagName==='BUTTON'&&node.getAttribute('aria-controls')==='evidence-hit-list');

  assert.deepEqual(filters.children.map(node=>node.getAttribute('aria-pressed')),['false','false','true','false']);
  assert.equal(status.textContent,'Showing 2 of 2 returned code results');
  assert.equal(list.children.length,2);
  assert.equal(toggle.hidden,true);
});

test('dedicated claim results render their compact shape without claiming RRF rank',()=>{
  const claims=[
    {claim:{id:21,text:'Prefer one migration owner.',updated_at:'2026-08-14T00:00:00Z'}},
    {claim:{id:22,text:'Let every worker migrate.',updated_at:'2026-08-14T00:00:00Z'}},
  ];
  const section=evidenceDomContext.renderEvidenceResults(claims,claims,'claim');
  const nodes=descendants(section);
  const filters=nodes.find(node=>node.className==='evidence-filters');
  const list=nodes.find(node=>node.className==='hit-list');
  const status=nodes.find(node=>node.getAttribute?.('role')==='status');

  assert.deepEqual(filters.children.map(node=>node.getAttribute('aria-pressed')),['false','false','false','true']);
  assert.equal(status.textContent,'Showing 2 of 2 returned claim results');
  assert.equal(list.children.length,2);
  assert.match(nodeText(list.children[0]),/Durable agent claim/);
  assert.match(nodeText(list.children[0]),/Claim #21/);
  assert.match(nodeText(list.children[0]),/Prefer one migration owner[.]/);
  assert.match(nodeText(list.children[0]),/Claim rank 1/);
  assert.doesNotMatch(nodeText(list.children[0]),/Fused rank/);
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
  assert.match(page,/else if\(hit[?][.]source==='markdown'\)\{\s*card[.]append\(renderInlineMarkdown\(snippet,hit\)\)/);
  assert.match(page,/if\(hit[?][.]source==='code'\)\{\s*const pre=element\('pre'\)/);
  assert.match(page,/JSON[.]stringify\(\{query,limit:20,category:selectedCategory\}\)/);
  assert.match(page,/typed claim search/);
  assert.match(page,/selectedCategory==='claim'\?'retrieved claims in':'retrieved \+ fused in'/);
  assert.match(page,/Where is the MCP server configured and which tools does it expose[?]/);
  assert.match(page,/What AWS services does this project use[?]/);
  assert.doesNotMatch(page,/innerHTML/);
});
