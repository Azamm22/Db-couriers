import sqlite3
from werkzeug.security import generate_password_hash

# Подключение к базе данных
conn = sqlite3.connect('courier_management.db')
cursor = conn.cursor()

# Данные администратора
admin_username = "admin"
admin_password = generate_password_hash("admin123")  # Пароль: admin123

# Вставка администратора в базу данных
cursor.execute('''
    INSERT INTO users (username, password, role)
    VALUES (?, ?, ?)
''', (admin_username, admin_password, 'admin'))

conn.commit()
conn.close()

print("Администратор успешно добавлен!")
