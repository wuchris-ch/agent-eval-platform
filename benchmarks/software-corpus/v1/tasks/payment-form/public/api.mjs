export function payment(db, request) {
  const amount = Number(request.amount_minor);
  if (!Number.isFinite(amount) || amount <= 0) return {status:422,error:'invalid_amount'};
  const row = db.prepare('INSERT INTO payments(amount_minor) VALUES(?)').run(amount);
  return {status:201,id:Number(row.lastInsertRowid),amount_minor:amount};
}
