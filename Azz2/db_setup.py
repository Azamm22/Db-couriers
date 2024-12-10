import sqlite3

# Подключение к базе данных
conn = sqlite3.connect('courier_management.db')
cursor = conn.cursor()

# Создание таблицы пользователей
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )
''')

# Создание таблицы заявок
cursor.execute('''
    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        full_name TEXT NOT NULL,
        contact_number TEXT NOT NULL,
        city TEXT NOT NULL,
        transport_type TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        reason TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
''')

# Создание таблицы курьеров (если требуется)
cursor.execute('''
    CREATE TABLE IF NOT EXISTS couriers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE,
        full_name TEXT NOT NULL,
        contact_number TEXT NOT NULL,
        city TEXT NOT NULL,
        transport_type TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
''')

# Закрытие подключения
conn.commit()
conn.close()

print("База данных успешно настроена!")
