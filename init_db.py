# init_db.py
import os
import psycopg2

# --- Configuration ---
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:Aakhan25@db.voprcjrogydljhcbjcqq.supabase.co:5432/postgres"
)

SCHEMA_FILE = "schema_postgres.sql"  # make sure this file is in the same folder

# --- Connect to DB ---
try:
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    print(f"Connected to database: {DATABASE_URL.split('@')[-1]}")
except Exception as e:
    print("Failed to connect to DB:", e)
    exit(1)

# --- Run schema ---
try:
    with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
        sql = f.read()
    cur.execute(sql)
    conn.commit()
    print("Database initialized successfully.")
except Exception as e:
    print("Failed to initialize DB:", e)
finally:
    cur.close()
    conn.close()
