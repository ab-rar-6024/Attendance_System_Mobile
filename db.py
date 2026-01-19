import os
import psycopg2

def connect_db():
    return psycopg2.connect(
        host="db.oebnbvzxgnsqwyhouqvv.supabase.co",
        database="postgres",
        user="postgres",
        password=os.getenv("SUPABASE_PASSWORD", "Abrar 2005#24"),
        port=5432
    )
