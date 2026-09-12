def handle(db, request):
    actor = request.get("actor")
    if actor is None:
        return {"status": 401}
    row = db.execute(
        "SELECT body FROM documents WHERE id=? AND tenant=? AND owner=?",
        (request["id"], actor["tenant"], actor["user"]),
    ).fetchone()
    if row is None:
        return {"status": 404}
    if request.get("op", "get") == "update":
        db.execute(
            "UPDATE documents SET body=? WHERE id=? AND tenant=? AND owner=?",
            (request["body"], request["id"], actor["tenant"], actor["user"]),
        )
        db.commit()
        return {"status": 204}
    return {"status": 200, "body": row[0]}
