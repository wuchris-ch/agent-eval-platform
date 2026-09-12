# Add timezone without breaking existing clients or data

The service starts with the existing users table `(id INTEGER PRIMARY KEY, name TEXT NOT NULL)` and an existing row for Alice. Replace the destructive migration in `migration.py` with an additive migration for `timezone TEXT NOT NULL DEFAULT 'UTC'`. Running the migration repeatedly must preserve every existing row, ID and timezone value.

The adapter's default v1 read response remains exactly `{status:200,id,name}`. Version 2 adds `timezone`. Existing create callers may omit timezone and receive UTC; newer callers may supply another value. Preserve the table and primary-key semantics. Do not reset the database to pass verification.

The public smoke check runs the migration once. Independent checks run it twice, read the old record through both API versions, create through an old client, create through a new client, rerun the migration, and inspect final rows.
