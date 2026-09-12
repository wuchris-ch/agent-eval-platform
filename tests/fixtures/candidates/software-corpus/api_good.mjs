export function payment(db, request) {
  const amount=request.amount_minor;
  if (typeof amount!=='number'||!Number.isSafeInteger(amount)||amount<1||amount>99999999) return {status:422,error:'invalid_amount'};
  const row=db.prepare('INSERT INTO payments(amount_minor) VALUES(?)').run(amount);
  return {status:201,id:Number(row.lastInsertRowid),amount_minor:amount};
}
