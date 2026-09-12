import json
import sys
from catalog import page

for line in sys.stdin:
    print(json.dumps(page(json.loads(line))),flush=True)
