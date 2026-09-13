import json
import sqlite3
import sys
from migration import migrate


def main():
    db=sqlite3.connect('/state/state.sqlite')
    db.execute('CREATE TABLE users(id INTEGER PRIMARY KEY,name TEXT NOT NULL)')
    db.execute('INSERT INTO users VALUES(1,?)',('Alice',))
    db.commit()
    for line in sys.stdin:
        request=json.loads(line)
        if request['op']=='migrate':
            migrate(db)
            result={'status':200}
        elif request['op']=='create':
            cursor=db.execute('INSERT INTO users(name,timezone) VALUES(?,?)',(request['name'],request.get('timezone','UTC')))
            db.commit()
            result={'status':201,'id':cursor.lastrowid}
        else:
            row=db.execute('SELECT id,name,timezone FROM users WHERE id=?',(request['id'],)).fetchone()
            result={'status':404} if row is None else {'status':200,'id':row[0],'name':row[1]}
            if row is not None and request.get('api_version',1)==2:
                result['timezone']=row[2]
        print(json.dumps(result),flush=True)
    db.close()


if __name__=='__main__':
    main()
