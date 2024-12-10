from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Деректер базасына қосылу функциясы
def get_db_connection():
    conn = sqlite3.connect('courier_management.db')  # add_admin.py файлымен сәйкес келетін атау
    conn.row_factory = sqlite3.Row
    return conn

# Басты бет
@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':  # Егер POST сұрауы болса, авторизация орындалады
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['role'] = user['role']
            session['user_id'] = user['id']  # user_id мәнін сессияда сақтау
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'courier':
                return redirect(url_for('courier_dashboard'))
        return render_template('login.html', error='Қате логин немесе құпиясөз')

    # Егер GET сұрауы болса, авторизация формасы көрсетіледі
    return render_template('login.html')

# Тіркелу
@app.route('/register', methods=['GET', 'POST'])
def register_post():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']  # Құпиясөзді растау

        # Құпиясөздердің сәйкес келуін тексеру
        if password != confirm_password:
            return render_template('register.html', error='Құпиясөздер сәйкес келмейді')

        # Құпиясөзді хэштеу
        hashed_password = generate_password_hash(password)

        # Жаңа қолданушыны деректер базасына қосу
        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                     (username, hashed_password, 'courier'))  # Рөлді 'courier' деп көрсетеміз
        conn.commit()
        conn.close()

        return redirect(url_for('home'))  # Тіркелгеннен кейін басты бетке қайта бағыттаймыз

    return render_template('register.html')  # GET сұрауы үшін тіркелу беті көрсетіледі

# Админ: Заявкалар
@app.route('/admin_dashboard')
def admin_dashboard():
    conn = get_db_connection()
    applications = conn.execute('SELECT * FROM applications WHERE status = "pending"').fetchall()
    conn.close()
    return render_template('admin_dashboard.html', applications=applications)

# Админ: Заявкалардың тарихы
@app.route('/admin_application_history')
def admin_application_history():
    if 'role' in session and session['role'] == 'admin':
        conn = get_db_connection()
        history = conn.execute('SELECT * FROM applications WHERE status IN ("accepted", "rejected")').fetchall()
        conn.close()
        return render_template('admin_application_history.html', history=history)
    return redirect(url_for('home'))

# Админ: Курьерлер
# "Курьерлер" беті
@app.route('/admin_couriers')
def admin_couriers():
    if 'role' in session and session['role'] == 'admin':
        # Деректер базасына қосылу
        conn = get_db_connection()

        # Қабылданған (status = 'accepted') және белсенді күйдегі (is_active = 1) курьерлер туралы мәліметтер алу
        couriers = conn.execute('''
            SELECT u.id, u.username, a.last_name, a.first_name, a.patronymic, a.contact_number, a.city, a.transport_type
            FROM users u
            JOIN applications a ON u.id = a.user_id
            WHERE u.role = 'courier' AND u.is_active = 1 AND a.status = 'accepted'
        ''').fetchall()

        # Деректер базасымен байланыс аяқталды
        conn.close()

        # Деректерді шаблонға жіберу
        return render_template('admin_couriers.html', couriers=couriers)

    # Егер админ емес болса, басты бетке қайта бағыттаймыз
    return redirect(url_for('home'))



# Курьер: Панель
# Курьер: Панель
@app.route('/courier_dashboard', methods=['GET', 'POST'])
def courier_dashboard():
    # Курьердің авторизацияланғанын тексереміз
    if 'username' not in session or session.get('role') != 'courier':
        return redirect(url_for('home'))  # Егер авторизацияланбаған болса, басты бетке қайта бағыттаймыз

    # Қолданушының мәліметтерін аламыз
    conn = get_db_connection()
    user_id = conn.execute('SELECT id FROM users WHERE username = ?', (session['username'],)).fetchone()['id']

    # Қолданушының өтінімін аламыз
    application = conn.execute('SELECT * FROM applications WHERE user_id = ?', (user_id,)).fetchone()

    # POST сұрауы өңделген кезде (форма жіберілген болса)
    if request.method == 'POST':
        # Өтінімнің бар-жоғын тексереміз
        if application:
            return redirect(url_for('application_confirmation'))  # Егер өтінім бар болса, растау бетіне қайта бағыттаймыз

        last_name = request.form['last_name']
        first_name = request.form['first_name']
        patronymic = request.form['patronymic']
        contact_number = request.form['contact_number']
        city = request.form['city']
        transport_type = request.form['transport_type']

        # Өтінімді деректер базасына енгіземіз
        conn.execute(''' 
            INSERT INTO applications (user_id, last_name, first_name, patronymic, contact_number, city, transport_type, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
        ''', (user_id, last_name, first_name, patronymic, contact_number, city, transport_type))
        conn.commit()

        # Форма жіберілгеннен кейін растау бетіне қайта бағыттаймыз
        return redirect(url_for('application_confirmation'))

    # Егер өтінім болмаса, "жаңа өтінім" деген статус орнатамыз
    status = application['status'] if application else "new"
    reason = application['reason'] if application and application['status'] == 'rejected' else None
    conn.close()

    # Шаблонды мәліметтермен қайтарамыз
    return render_template('dashboard.html', status=status, reason=reason)


# "Өтінімдер" беті
@app.route('/admin_applications', methods=['GET', 'POST'])
def admin_applications():
    if 'role' in session and session['role'] == 'admin':
        conn = get_db_connection()

        # POST сұрауы болса (мысалы, өтінімдермен әрекеттер: қабылдау/қабылдамау)
        if request.method == 'POST':
            action = request.form['action']
            application_id = request.form['application_id']

            # Өтінімді қабылдау өңдеуі
            if action == 'accept':
                # Өтінімнің статусын "қабылданды" деп жаңартамыз
                conn.execute('''
                    UPDATE applications
                    SET status = 'accepted'
                    WHERE id = ?
                ''', (application_id,))

                # Курьердің статусын "белсенді" деп жаңартамыз
                conn.execute('''
                    UPDATE users
                    SET is_active = 1
                    WHERE id = (SELECT user_id FROM applications WHERE id = ?)
                ''', (application_id,))

            # Өтінімді қабылдамау өңдеуі
            elif action == 'reject':
                reason = request.form['reason']
                # Өтінімнің статусын "қабылданбады" деп жаңартып, бас тарту себебін сақтаймыз
                conn.execute('''
                    UPDATE applications
                    SET status = 'rejected', reason = ?
                    WHERE id = ?
                ''', (reason, application_id))

                # Қабылданбаған өтінімді деректер базасынан жоямыз
                conn.execute('''
                    DELETE FROM applications WHERE id = ?
                ''', (application_id,))

            # Өзгерістерді сақтаймыз
            conn.commit()

            # Өтінімдер бетіне қайта бағыттаймыз
            return redirect(url_for('admin_applications'))

        # Барлық өтінімдерді деректер базасынан аламыз
        applications = conn.execute('SELECT * FROM applications').fetchall()
        conn.close()

        # Өтінімдерді бетте көрсетеміз
        return render_template('admin_applications.html', applications=applications)

    # Егер қолданушы админ болмаса, басты бетке қайта бағыттаймыз
    return redirect(url_for('home'))


@app.route('/admin_statistics')
def admin_statistics():
    if 'role' in session and session['role'] == 'admin':
        conn = get_db_connection()

        total_applications = conn.execute('SELECT COUNT(*) FROM applications').fetchone()[0]
        accepted_applications = conn.execute('SELECT COUNT(*) FROM applications WHERE status = "accepted"').fetchone()[0]
        rejected_applications = conn.execute('SELECT COUNT(*) FROM applications WHERE status = "rejected"').fetchone()[0]
        pending_applications = conn.execute('SELECT COUNT(*) FROM applications WHERE status = "pending"').fetchone()[0]
        total_couriers = conn.execute('SELECT COUNT(*) FROM users WHERE role = "courier"').fetchone()[0]

        conn.close()

        return render_template(
            'admin_statistics.html',
            total_applications=total_applications,
            accepted_applications=accepted_applications,
            rejected_applications=rejected_applications,
            pending_applications=pending_applications,
            total_couriers=total_couriers
        )
    return redirect(url_for('home'))


# Страница "Тренды"
@app.route('/admin_trends')
def admin_trends():
    if 'role' in session and session['role'] == 'admin':
        conn = get_db_connection()

        trends = conn.execute('''
            SELECT strftime('%Y-%m', timestamp) AS month, transport_type, COUNT(*) AS applications_count
            FROM applications
            GROUP BY month, transport_type
            ORDER BY month DESC;
        ''').fetchall()

        conn.close()
        return render_template('admin_trends.html', trends=trends)
    return redirect(url_for('home'))


@app.route('/application_confirmation')
def application_confirmation():
    if 'username' in session and session.get('role') == 'courier':
        # Өтінімнің бар-жоғын тексереміз
        conn = get_db_connection()
        user_id = conn.execute('SELECT id FROM users WHERE username = ?', (session['username'],)).fetchone()['id']
        application = conn.execute('SELECT * FROM applications WHERE user_id = ?', (user_id,)).fetchone()

        if application and application['status'] == 'pending':
            return render_template('application_confirmation.html')  # Өтінімді растау бетіне көрсетеміз
        else:
            return redirect(url_for('courier_dashboard'))  # Өтінім жоқ болса, курьердің панеліне қайта бағыттаймыз

    return redirect(url_for('home'))  # Егер қолданушы авторизацияланбаса, басты бетке қайта бағыттаймыз


@app.route('/courier_info', methods=['GET', 'POST'])
def courier_info():
    if 'role' in session and session['role'] == 'courier':
        return render_template('courier_info.html')
    return redirect(url_for('home'))


@app.route('/application', methods=['GET', 'POST'])
def application():
    if 'role' in session and session['role'] == 'courier':
        user_id = session['user_id']

        # Курьердің өтінімі бар-жоғын тексереміз
        conn = get_db_connection()
        application_exists = conn.execute(
            'SELECT * FROM applications WHERE user_id = ?', (user_id,)
        ).fetchone()

        if application_exists:
            if application_exists['status'] == 'pending':
                return "Сіздің өтініміңіз қарастырылуда."
            elif application_exists['status'] == 'accepted':
                return redirect(url_for('courier_dashboard'))  # Курьердің панеліне қайта бағыттаймыз
            elif application_exists['status'] == 'rejected':
                return f"Өтінім қабылданбады. Себебі: {application_exists['reason']}"

        if request.method == 'POST':  # Бұл блок POST сұрауы болғанда орындалады
            last_name = request.form['last_name']
            first_name = request.form['first_name']
            patronymic = request.form['patronymic']
            contact_number = request.form['contact_number']
            city = request.form['city']
            transport_type = request.form['transport_type']

            # Өтінімді деректер базасына енгіземіз
            conn.execute(''' 
                INSERT INTO applications (user_id, last_name, first_name, patronymic, contact_number, city, transport_type, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
            ''', (user_id, last_name, first_name, patronymic, contact_number, city, transport_type))
            conn.commit()
            conn.close()

            return redirect(url_for('application_confirmation'))  # Өтінімді растау бетіне қайта бағыттаймыз

        conn.close()
        return render_template('application.html')  # GET сұрауы болса, өтінім формасын көрсетеміз
    return redirect(url_for('home'))  # Егер авторизацияланбаған болса, басты бетке қайта бағыттаймыз


# Шығу
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
