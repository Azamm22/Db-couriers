import sqlite3

# Подключение к базе данных
conn = sqlite3.connect('courier_management.db')
cursor = conn.cursor()

# Создание таблицы для заявок курьеров
cursor.execute('''
    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        full_name TEXT NOT NULL,
        contact_number TEXT NOT NULL,
        city TEXT NOT NULL,
        transport_type TEXT NOT NULL,
        status TEXT DEFAULT 'pending', -- Статусы: pending, accepted, rejected
        reason TEXT DEFAULT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
''')

# Обновление таблицы пользователей для добавления статуса активации
cursor.execute('''
    ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 0
''')

conn.commit()
conn.close()

print("База данных обновлена!")
