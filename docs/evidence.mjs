import {previewDecision,visibleRows} from './evidence-logic.mjs';
const $=id=>document.getElementById(id);
const el=(tag,value,cls)=>{const node=document.createElement(tag);node.textContent=value??'';if(cls)node.className=cls;return node;};
const fmt=(value,unit='',digits=1)=>value==null?'Not measured':Number(value).toLocaleString(undefined,{maximumFractionDigits:digits})+unit;
const label={pass:'Accepted',fail:'Rejected',inconclusive:'Inconclusive',production_failed:'Production failed',pending:'Pending'};
let catalog,active,selected=null;
function badge(outcome){return el('span',label[outcome]||outcome,'badge '+outcome);}
function metric(name,value,note){const box=el('div','','metric');box.append(el('div',name,'label'),el('div',value,'value'),el('div',note,'note'));return box;}
function renderCollection(){
  active=catalog.collections.find(item=>item.id===$('collection').value);if(!active)return;
  $('latency-heading').textContent=active.latency_label||'Latency';$('kind').textContent=active.kind_label;$('collection-title').textContent=active.title;$('description').textContent=active.description;$('revision').textContent=active.revision_label;
  $('inference').textContent=active.inference;$('download').href=active.download;$('report-link').href=active.report;
  $('metrics').replaceChildren(...active.metrics.map(m=>metric(m.label,m.value,m.note)));
  $('arm-comparison').replaceChildren();
  for(const arm of active.arms||[]){const box=el('div','','arm'),head=el('div','','arm-heading'),bar=el('div','','bar');head.append(el('strong',arm.label),el('span',`${arm.accepted} / ${arm.planned} accepted`));for(const [count,cls] of [[arm.accepted,'pass'],[arm.rejected,'fail'],[arm.planned-arm.accepted-arm.rejected,'unknown']]){const part=el('span','',cls);part.style.width=(arm.planned?count/arm.planned*100:0)+'%';bar.append(part);}box.append(head,bar,el('small',arm.note));$('arm-comparison').append(box);}
  $('policy-section').hidden=!active.policy_replay;$('outcome').value='all';$('attempt').value='initial';$('search').value='';selected=null;renderRows();renderPreview();
}
function renderRows(){
  const rows=visibleRows(active.rows,{outcome:$('outcome').value,attempt:$('attempt').value,search:$('search').value});
  $('row-count').textContent=`${rows.length} of ${active.rows.length} recorded attempts`;$('empty').hidden=rows.length>0;$('rows').replaceChildren();
  for(const row of rows){const tr=el('tr','');tr.dataset.execution=row.execution_id||row.row_id;const title=el('td',''),button=el('button',row.task_id,'row-button');button.append(el('small',`${row.family} · trial ${row.trial}`));button.onclick=()=>selectRow(row,true);title.append(button);const status=el('td','');status.append(badge(row.outcome));tr.append(title,el('td',row.arm_label||row.arm),status,el('td',fmt(row.usage?.latency_ms==null?null:row.usage.latency_ms/1000,' s')));$('rows').append(tr);}
  const chosen=rows.find(row=>(row.execution_id||row.row_id)===selected)||rows.find(row=>row.outcome==='fail')||rows[0];
  if(chosen)selectRow(chosen);else{$('detail').replaceChildren(el('p','TRIAL RECEIPT','eyebrow'),el('h3','No matching results'),el('p','Adjust the filters to inspect another result.','muted'));}
}
function selectRow(row,scroll=false){
  selected=row.execution_id||row.row_id;for(const tr of $('rows').children)tr.classList.toggle('selected',tr.dataset.execution===selected);
  const panel=$('detail');panel.replaceChildren(el('p','TRIAL RECEIPT','eyebrow'),el('h3',row.task_id),badge(row.outcome));
  const note=row.reasons?.join('; ')||(row.outcome==='pass'?'All required checks matched.':row.outcome==='production_failed'?'The producer did not return an assessable candidate.':row.outcome==='pending'?'This reserved trial has not finished.':'The available evidence did not establish acceptance.');panel.append(el('p',note,'muted'));
  const stats=el('div','','detail-stats');for(const [name,value] of [[active.latency_label||'Latency',fmt(row.usage?.latency_ms==null?null:row.usage.latency_ms/1000,' s')],['Tokens',fmt(row.usage?.total_tokens,'',0)],['Cost (USD)',fmt(row.usage?.cost_usd,'',4)]]){const item=el('span',name);item.append(el('strong',value));stats.append(item);}panel.append(stats);if(row.usage?.provenance)panel.append(el('p','Measurement provenance: '+row.usage.provenance.replaceAll('_',' ')+'.','muted'));
  for(const check of row.checks||[]){const item=el('div','','check '+(check.passed?'':'failed'));item.append(el('span',check.passed?'✓':'×','check-icon'),el('strong',check.description||check.id.replaceAll('-',' ')),el('p',check.reason));if(check.expected_state!==undefined || check.expected_responses!==undefined){const values=el('details','','observation-detail');values.append(el('summary','Compare expected and observed'));const pre=el('pre',JSON.stringify({expected_responses:check.expected_responses,observed_responses:check.observed_responses,expected_state:check.expected_state,observed_state:check.observed_state},null,2));values.append(pre);item.append(values);}panel.append(item);}
  if(row.phases?.length){const phases=el('details','','identity-list');phases.append(el('summary','Production stages and request counts'));for(const phase of row.phases)phases.append(el('p',`${phase.stage}: ${phase.status}, ${fmt(phase.model_requests,' requests',0)}, ${fmt(phase.duration_seconds,' s')}`,'muted'));panel.append(phases);}
  if(row.reported_accounting?.model_requests!=null)panel.append(el('p',`Producer-reported requests: ${row.reported_accounting.model_requests}. Reported tokens: ${fmt(row.reported_accounting.total_tokens,'',0)}.`,'muted'));
  if(row.note)panel.append(el('p',row.note,'muted'));
  const details=el('details','','identity-list');details.append(el('summary','Execution identity & receipt chain'));const list=el('dl','');for(const [name,key] of [['Execution','execution_id'],['Candidate tree','candidate_tree_sha256'],['Trial ticket','trial_ticket_sha256'],['Submission','submission_sha256'],['Observation','observation_sha256'],['Assessment','assessment_sha256'],['Recipe','recipe_sha256'],['Suite','suite_sha256'],['Policy','policy_sha256'],['Evaluator','evaluator_sha256']])if(row[key])list.append(el('dt',name),el('dd',row[key]));details.append(list);panel.append(details);if(scroll&&matchMedia("(max-width:900px)").matches)panel.scrollIntoView({behavior:"smooth",block:"start"});
}
function renderPreview(){
  if(!active.policy_replay)return;
  const metric=$('policy-metric').value;$('policy-limit').disabled=metric==='none';$('policy-unit').textContent=metric==='latency_ms'?'seconds':metric==='total_tokens'?'tokens':metric==='cost_usd'?'USD':'';
  const amount=Number($('policy-limit').value);if(metric!=='none'&&(!Number.isFinite(amount)||amount<0||(metric==='latency_ms'&&amount===0)||(metric==='total_tokens'&&!Number.isInteger(amount)))){$('policy-preview').replaceChildren(el('p','Enter a positive latency, a whole token count, or a nonnegative cost.'));return;}
  const limits=metric==='none'?{}:{[metric]:amount*(metric==='latency_ms'?1000:1)},counts={pass:0,fail:0,inconclusive:0};
  for(const row of active.rows.filter(r=>r.attempt_kind==='initial'))counts[previewDecision(row,limits)]++;
  $('policy-preview').replaceChildren(...Object.entries(counts).map(([outcome,count])=>{const card=el('div','','preview-card');card.append(el('strong',count),document.createTextNode(label[outcome].toLowerCase()+' in preview'));return card;}));
}
try{
  const response=await fetch('evidence/index.json',{cache:'no-cache'});if(!response.ok)throw new Error('Evidence is currently unavailable.');catalog=await response.json();
  await Promise.all(catalog.collections.map(async collection=>{collection.rows=(await Promise.all(collection.rows_files.map(async path=>{const part=await fetch(path);if(!part.ok)throw new Error('A recorded evidence file is unavailable.');return part.json();}))).flat();}));
  $('published').textContent='Recorded '+catalog.recorded_at;
  for(const collection of catalog.collections){const option=el('option',collection.title);option.value=collection.id;$('collection').append(option);}
  const requested=new URLSearchParams(location.search).get('collection');if(catalog.collections.some(c=>c.id===requested))$('collection').value=requested;
  $('collection').onchange=()=>{const url=new URL(location);url.searchParams.set('collection',$('collection').value);history.replaceState(null,'',url);renderCollection();};
  for(const id of ['outcome','attempt','search'])$(id).addEventListener(id==='search'?'input':'change',renderRows);
  for(const id of ['policy-metric','policy-limit'])$(id).addEventListener('input',renderPreview);
  $('status').textContent='';renderCollection();
}catch(error){$('status').textContent=error.message;}
