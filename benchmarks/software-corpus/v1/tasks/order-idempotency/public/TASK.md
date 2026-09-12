# Make order creation idempotent

The line-delimited JSON adapter in `server.py` represents POST /orders. A request carries an authenticated tenant, an idempotency key, and a positive integer amount in cents.

For the first valid request return `{status:201, order_id:<id>, amount:<amount>}`. Repeating the same key and amount within a tenant must return the original response and create no additional order. Reusing a key with a different amount must return `{status:409}` without changing any stored order. Keys are scoped to a tenant. Reject nonpositive amounts with `{status:422}` and no database changes. Preserve existing order IDs and the `orders` table. The service uses SQLite at `/state/state.sqlite`.

The public smoke check is one positive request. Independent verification includes replay, conflicting payloads, tenant isolation, invalid amounts, and final stored rows.
