# Payment form and API contract

Repair the browser form and payment API. Keep their existing module exports and response shapes. The form must call the same API contract used by direct clients. The JSONL driver exercises those exported production functions and the evaluator independently queries the final payments table.

The form accepts a trimmed decimal string with an integer part and up to two fractional digits, between 0.01 and 999999.99 inclusive. Leading zeros other than the single zero before a decimal point, signs, exponent notation, an empty string, and more than two decimal places are invalid. Convert valid input to exact integer cents. For example, ` 12.30 ` becomes 1230. Invalid form input returns `{status:422,field_error:"Enter a valid amount",receipt:null}` without calling the API.

The API accepts only a JSON number that is a safe integer between 1 and 99999999 inclusive as `amount_minor`. Strings, booleans, fractions, and out-of-range values return `{status:422,error:"invalid_amount"}` without writing. Each accepted request inserts one payment and returns `{status:201,id:<id>,amount_minor:<cents>}`. IDs start at 1 and increase only on successful insertions.

Successful form submission returns `{status:201,field_error:null,receipt:{id:<id>,amount_minor:<cents>}}`. An API rejection must replace any receipt with null and show the field error. The HTML entrypoint uses this same form function. Only `client.mjs` and `api.mjs` may change; keep `server.mjs` and `index.html` intact.
