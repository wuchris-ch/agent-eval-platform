def migrate(db):
    db.execute('DROP TABLE users')
    db.execute("CREATE TABLE users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,timezone TEXT NOT NULL DEFAULT 'UTC')")
    db.commit()
