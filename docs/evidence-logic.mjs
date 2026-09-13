export function previewDecision(row, limits={}) {
  if (!row.assessment_sha256 || !row.checks?.length) return 'inconclusive';
  if (row.checks.some(check=>!check.passed)) return 'fail';
  let missing = row.producer_completed === false;
  for (const [metric, maximum] of Object.entries(limits)) {
    if (!['latency_ms','total_tokens','cost_usd'].includes(metric) || !Number.isFinite(maximum) || maximum < 0 || (metric==='latency_ms'&&maximum===0) || (metric==='total_tokens'&&!Number.isInteger(maximum))) throw new Error('Invalid resource limit');
    const value=row.usage?.[metric];
    if (value==null || row.usage?.provenance!=='independently_observed') missing=true;
    else if(value>maximum)return 'fail';
  }
  return missing?'inconclusive':'pass';
}
export function visibleRows(rows, {outcome='all',attempt='initial',search=''}={}) {
  const query=search.toLowerCase();
  return rows.filter(row=>(outcome==='all'||row.outcome===outcome)&&(attempt==='all'||row.attempt_kind===attempt)&&`${row.task_id} ${row.family}`.toLowerCase().includes(query));
}
