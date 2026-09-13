export async function submitForm(value, send) {
  const amount_minor = Math.round(Number(value) * 100);
  const result = await send({amount_minor});
  if (result.status !== 201) return {status:422,field_error:'Enter a valid amount',receipt:null};
  return {status:201,field_error:null,receipt:{id:result.id,amount_minor:result.amount_minor}};
}
