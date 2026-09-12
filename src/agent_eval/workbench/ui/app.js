'use strict';
const $ = id => document.getElementById(id);
let token = sessionStorage.getItem('ae-session') || '';
if (location.hash.startsWith('#token=')) { token = decodeURIComponent(location.hash.slice(7)); sessionStorage.setItem('ae-session', token); history.replaceState(null, '', '/'); }
let runs = [], next = null, selected = null, revision = 0, frozenLaunch = null, launchKey = null, busy = false;
const text = (tag, value, cls) => { const e = document.createElement(tag); e.textContent = value; if (cls) e.className = cls; return e; };
function notice(value) { $('notice').textContent = value; }
async function api(path, body, extra = {}) {
  const response = await fetch('/v1/' + path, {method: body === undefined ? 'GET' : 'POST', headers: {'Authorization':'Bearer '+token,'X-Project':$('project').value,'Content-Type':'application/json',...extra}, ...(body === undefined ? {} : {body:JSON.stringify(body)})});
  const data = await response.json();
  if (!response.ok) { if (response.status === 403) $('login').hidden = false; throw new Error(data.error || 'Request failed'); }
  return data;
}
async function action(fn) { try { notice(''); await fn(); } catch (e) { notice(e.message); } }
function options(id, values, label) { const old = $(id).value; $(id).replaceChildren(...values.map(v => { const o=text('option',label(v)); o.value=v.id; return o; })); if (values.some(v=>v.id===old)) $(id).value=old; }
function tab(name) { for (const n of ['runs','compare','launch','review']) { $(n).hidden=n!==name; $('tab-'+n).classList.toggle('active',n===name); } }
for(const n of ['runs','compare','launch','review']) $('tab-'+n).onclick=()=>tab(n);
function button(label, fn) { const b=text('button',label); b.onclick=()=>action(fn); return b; }
async function evidence(id, ordinal) {
  const d=await api(`experiments/${id}/trials/${ordinal}`); selected={id,ordinal};
  $('evidence-title').textContent=`${d.case.id} · trial ${d.trial} · ${d.state}`;
  $('case').textContent=JSON.stringify(d.case,null,2); $('result').textContent=JSON.stringify(d.result,null,2) || 'Unavailable';
  $('state-evidence').textContent=d.state_evidence ? JSON.stringify(d.state_evidence,null,2) : 'No independent state observer configured.';
  $('trace').hidden=true;
  if(d.trace_url) { try { const u=new URL(d.trace_url); if(['http:','https:'].includes(u.protocol)) { $('trace').href=u.href; $('trace').hidden=false; } } catch (_) {} }
  $('annotations').replaceChildren(...d.annotations.map(a=>{const e=text('div',a.body,'annotation'); e.append(text('small',`${a.actor} · revision ${a.revision}`));return e;}));
  revision=d.annotations.at(-1)?.revision || 0; $('evidence').hidden=false; $('evidence').scrollIntoView({behavior:'smooth',block:'start'});
}
function renderRuns() {
  $('run-list').replaceChildren();
  if(!runs.length) $('run-list').append(text('p','No experiments yet. Launch a registered target, or run workbench demo from the CLI.','muted'));
  for(const r of runs) {
    const v=r.value, card=text('article','','card'), head=text('div','','card-head');
    head.append(text('h3',v.agent || r.id),text('span',v.state,'badge '+(v.overall_passed===true?'accepted':v.overall_passed===false?'rejected':'')));card.append(head);
    const metrics=text('div','','metrics');for(const [n,label] of [[v.completed,'completed'],[v.planned,'planned'],[v.accepted,'accepted'],[v.infra_errors,'unavailable']]){const m=text('span','');m.append(text('strong',n??'unavailable'),text('span',label));metrics.append(m);}card.append(metrics);
    if(v.inspection) card.append(text('p',`${v.inspection.required?'Required':'Optional'} inspection: ${v.inspection.status}`,'muted'));
    if(v.state_assessments?.length) card.append(text('p',`Independent state: ${v.state_assessments.filter(a=>a.status==='accepted').length}/${v.state_assessments.length} accepted`,'muted'));
    const trials=text('div','','trials');for(const t of v.trials || [])trials.append(button(`${t.ordinal+1} · ${t.state}`,()=>evidence(r.id,t.ordinal)));card.append(trials);
    const actions=text('div','','card-actions'); if(['queued','in_progress'].includes(v.state)) {actions.append(button('Start / resume',async()=>{await api(`experiments/${r.id}/start`,{});notice('Execution queued. Progress will refresh.');}),button('Cancel',async()=>{await api(`experiments/${r.id}/cancel`,{});notice('Cancellation requested. Unconfirmed effects remain visible.');}));}card.append(actions);$('run-list').append(card);
  }
  options('baseline',runs,r=>`${r.value.agent || r.id} · ${r.id.slice(0,8)}`);options('candidate',runs,r=>`${r.value.agent || r.id} · ${r.id.slice(0,8)}`); $('more').hidden=!next;
}
async function refresh(append=false) {
  if(busy)return;busy=true;
  try {const page=await api('experiments'+(append&&next?'?after='+encodeURIComponent(next):''));runs=append?[...runs,...page.items]:page.items;next=page.next;renderRuns();$('login').hidden=true;} finally {busy=false;}
}
$('connect').onclick=()=>action(async()=>{token=$('token').value;sessionStorage.setItem('ae-session',token);$('token').value='';await initialize();});
$('refresh').onclick=()=>action(()=>refresh());$('more').onclick=()=>action(()=>refresh(true));$('project').onchange=()=>action(()=>initialize());
$('close-evidence').onclick=()=>{$('evidence').hidden=true;selected=null;};
$('save-annotation').onclick=()=>action(async()=>{if(!selected)throw new Error('Select a trial first.');const body=$('annotation').value;await api(`experiments/${selected.id}/trials/${selected.ordinal}/annotations`,{body,expected_revision:revision});$('annotation').value='';await evidence(selected.id,selected.ordinal);notice('Annotation saved.');});
$('compare-button').onclick=()=>action(async()=>{
  const baseline=$('baseline').value,candidate=$('candidate').value;
  const d=await api(`comparisons?baseline=${encodeURIComponent(baseline)}&candidate=${encodeURIComponent(candidate)}`), container=$('comparison');container.replaceChildren();
  container.append(text('p',d.reasons.length?'Inconclusive: '+d.reasons.join('; '):`Candidate effect: ${(100*d.effect).toFixed(1)} percentage points. 95% interval: ${d.interval?.map(v=>(100*v).toFixed(1)).join(' to ') ?? 'unavailable'}.`));
  for(const arm of ['baseline','candidate']){const c=d.counts[arm];container.append(text('p',`${arm}: ${c.accepted}/${c.planned} accepted; ${c.completed} completed; ${c.infrastructure} infrastructure failures. Conditional quality: ${c.conditional_quality===null?'unavailable':(c.conditional_quality*100).toFixed(1)+'%'}.`,'muted'));}
  container.append(text('p',d.limitations,'muted'));const table=document.createElement('table'),header=document.createElement('tr');for(const h of ['Case','Trial','Baseline','Candidate','Evidence'])header.append(text('th',h));table.append(header);
  for(const c of d.cases){const tr=document.createElement('tr');for(const value of [c.case,c.trial,c.baseline,c.candidate])tr.append(text('td',value));const cell=document.createElement('td');cell.append(button('Baseline',()=>evidence(baseline,c.baseline_ordinal)),document.createTextNode(' '),button('Candidate',()=>evidence(candidate,c.candidate_ordinal)));tr.append(cell);table.append(tr);}container.append(table);
});
function launchInput(){return {target:$('target').value,dataset:$('dataset').value,trials:Number($('trials').value),budget_acknowledged:$('budget').checked};}
for(const id of ['target','dataset','trials','budget']) $(id).onchange=()=>{frozenLaunch=null;$('launch-button').hidden=true;};
$('preview-button').onclick=()=>action(async()=>{const body=launchInput();const p=await api('preview',body);frozenLaunch=body;launchKey=crypto.randomUUID();$('preview').textContent=JSON.stringify(p,null,2);$('launch-button').hidden=false;});
$('launch-button').onclick=()=>action(async()=>{if(!frozenLaunch)throw new Error('Preview the current launch first.');const d=await api('experiments',frozenLaunch,{'Idempotency-Key':launchKey});await api(`experiments/${d.experiment_id}/start`,{});frozenLaunch=null;$('launch-button').hidden=true;tab('runs');await refresh();});
async function initialize(){await refresh();const [targets,datasets]=await Promise.all([api('targets'),api('datasets')]);options('target',targets.items,v=>v.value.name);options('dataset',datasets.items.filter(v=>v.value.split!=='held_out'),v=>`${v.value.name} (${v.value.cases} cases)`);}
if(token)action(initialize);else $('login').hidden=false;
setInterval(()=>{if(token&&!document.hidden&&!$('runs').hidden)action(()=>refresh());},4000);

$('load-review').onclick=()=>action(async()=>{const notes=await api('review');$('review-list').replaceChildren(...notes.map(n=>{const e=text('article','','card');e.append(text('p',n.body),text('small',`${n.actor} · revision ${n.revision}`),button('Open evidence',()=>evidence(n.experiment,n.ordinal)));return e;}));if(!notes.length)$('review-list').append(text('p','No investigation notes yet.','muted'));});
