import sqlite3

conn = sqlite3.connect("db/iseg.db")
cursor = conn.cursor()

cursor.execute("PRAGMA table_info(vote_records);")
columns = cursor.fetchall()

print("🔍 Стовпці таблиці vote_records:")
for col in columns:
    print(f"{col[1]} ({col[2]})")

conn.close()
