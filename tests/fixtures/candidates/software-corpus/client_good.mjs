export async function submitForm(value, send) {
  const error={status:422,field_error:'Enter a valid amount',receipt:null};
  if (typeof value !== 'string') return error;
  const clean=value.trim();
  if (!/^(0|[1-9][0-9]*)(\.[0-9]{1,2})?$/.test(clean)) return error;
  const [whole,fraction='']=clean.split('.');
  const amount_minor=Number(whole)*100+Number(fraction.padEnd(2,'0'));
  if (!Number.isSafeInteger(amount_minor)||amount_minor<1||amount_minor>99999999) return error;
  const result=await send({amount_minor});
  if(result.status!==201)return error;
  return {status:201,field_error:null,receipt:{id:result.id,amount_minor:result.amount_minor}};
}
