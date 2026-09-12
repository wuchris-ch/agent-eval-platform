def migrate(db):
    columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
    if "timezone" not in columns:
        db.execute("ALTER TABLE users ADD COLUMN timezone TEXT NOT NULL DEFAULT 'UTC'")
    db.commit()
