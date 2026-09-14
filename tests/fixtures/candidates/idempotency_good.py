"""Known positive control, excluded from producer workspaces."""

import json
import sqlite3
import sys


def request(db, value):
    tenant, key, amount = value["tenant"], value["key"], value["amount"]
    if amount <= 0:
        return {"status": 422}
    with db:
        old = db.execute(
            "SELECT id,amount FROM orders WHERE tenant=? AND request_key=?",
            (tenant, key),
        ).fetchone()
        if old:
            return (
                {"status": 201, "order_id": old[0], "amount": old[1]}
                if old[1] == amount
                else {"status": 409}
            )
        cursor = db.execute(
            "INSERT INTO orders(tenant,request_key,amount) VALUES(?,?,?)",
            (tenant, key, amount),
        )
        return {"status": 201, "order_id": cursor.lastrowid, "amount": amount}


def main():
    db = sqlite3.connect("/state/state.sqlite")
    db.execute(
        "CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, tenant TEXT, request_key TEXT, amount INTEGER)"
    )
    db.commit()
    for line in sys.stdin:
        print(json.dumps(request(db, json.loads(line))), flush=True)
    db.close()


if __name__ == "__main__":
    main()
