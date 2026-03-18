# Syncing Your Database With the Main Repo

To make your local database match the schema expected by the main repo code:

---

## Option 1: Run Pending Migrations (recommended)

Use this when you've pulled the latest code and only need to apply new migrations.

1. **Pull latest from main**
   ```bash
   git fetch origin main
   git checkout main   # or merge main into your branch
   git pull origin main
   ```

2. **Start the app** (migrations run automatically when `DB_MIGRATIONS_RUN=true` in `.env`)
   ```bash
   npm run start:dev
   ```
   On startup, TypeORM runs any migration that isn’t in the `migrations` table. Your schema will match the main repo.

3. **Or run migrations via CLI** (without starting the server)
   ```bash
   npm run build
   npm run typeorm:migration:run
   ```
   The CLI uses the built files in `dist/`, so `npm run build` is required first.

---

## Option 2: Full Reset (clean database, then re-run all migrations)

Use this when your database is broken, out of sync, or you want a clean state matching main.

**Warning:** This deletes all data in your local database.

1. **Pull latest from main** (as in Option 1).

2. **Drop and recreate the database** (PostgreSQL):

   In **psql** or **pgAdmin** (replace `home_health_ai` if your `DB_NAME` in `.env` is different):

   ```sql
   -- Disconnect any app/connections to the DB, then:
   DROP DATABASE IF EXISTS home_health_ai;
   CREATE DATABASE home_health_ai;
   ```

   Or from **PowerShell** (Windows) with `psql` in PATH:

   ```powershell
   $env:PGPASSWORD = "12345678"   # your DB_PASSWORD from .env
   psql -U postgres -h localhost -c "DROP DATABASE IF EXISTS home_health_ai;"
   psql -U postgres -h localhost -c "CREATE DATABASE home_health_ai;"
   ```

3. **Start the app** so all migrations run from scratch:

   ```bash
   npm run start:dev
   ```

   Every migration in `src/database/migrations/` will run in order; your database will match the main repo schema.

---

## Check that migrations ran

- In PostgreSQL, the table `migrations` lists which migrations have been applied.
- If the app starts without migration errors and your routes work, the schema is in sync.

---

## Your `.env` settings

- **DB_MIGRATIONS_RUN=true** – Migrations run automatically on app startup (recommended for dev).
- **DB_SYNCHRONIZE** – Leave **false**. Let migrations define the schema; do not use sync to “match” main.
