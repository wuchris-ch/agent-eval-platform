ROWS=[{'id':1,'timestamp':10,'name':'One'},{'id':2,'timestamp':10,'name':'Two'},{'id':3,'timestamp':10,'name':'Three'},{'id':4,'timestamp':11,'name':'Four'},{'id':5,'timestamp':12,'name':'Five'}]


def page(request):
    limit=request['limit']
    cursor=request.get('cursor')
    minimum=int(cursor.split(':')[0]) if cursor else -1
    available=[row for row in ROWS if row['timestamp']>minimum]
    selected=available[:limit]
    next_cursor=f"{selected[-1]['timestamp']}:{selected[-1]['id']}" if len(selected)==limit else None
    return {'items':selected,'next_cursor':next_cursor}
