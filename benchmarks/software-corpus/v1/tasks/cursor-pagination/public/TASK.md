# Preserve every record across cursor pages

The catalog endpoint orders records by `(timestamp,id)`, ascending. Timestamps are not unique. Fix the continuation logic in `catalog.py` so pages never skip or repeat a record with the same timestamp.

The public wire format uses a cursor string `<timestamp>:<id>` identifying the last returned record. A continuation returns records strictly after that complete tuple. `next_cursor` is the last returned tuple only when additional records remain, otherwise null, including when the final page happens to contain exactly the requested limit. A missing cursor starts at the beginning. A supplied limit is a positive integer. Preserve the existing items and JSON response shape.

The public smoke case requests the first two records. Independent checks follow duplicate timestamps, visit the final page, request an empty continuation and use a limit that exactly fills the last page.
