import json
import sqlite3
import sys
from documents import handle


def main():
    db = sqlite3.connect('/state/state.sqlite')
    db.execute('CREATE TABLE documents(id TEXT PRIMARY KEY,tenant TEXT,owner TEXT,body TEXT)')
    db.executemany('INSERT INTO documents VALUES(?,?,?,?)', [('n1','north','amy','Alpha'),('n2','north','ben','Beta'),('s1','south','amy','Gamma')])
    db.commit()
    for line in sys.stdin:
        print(json.dumps(handle(db,json.loads(line))),flush=True)
    db.close()


if __name__ == '__main__':
    main()
