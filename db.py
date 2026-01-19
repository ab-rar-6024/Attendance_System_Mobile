import os
import psycopg2

def connect_db():
    return psycopg2.connect(
        os.getenv("DATABASE_URL"),
        sslmode="require"
    )
