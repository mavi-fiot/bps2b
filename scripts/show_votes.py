import sqlite3
import os

db_path = "db/iseg.db"
print("Шлях до БД:", os.path.abspath(db_path))

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

cursor.execute("SELECT * FROM vote_records")
rows = cursor.fetchall()

print(f"Всього записів: {len(rows)}")
for row in rows:
    print(row, "в БД db/iseg.db")

conn.close()