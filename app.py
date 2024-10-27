from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_session import Session
from flask_mysqldb import MySQL
from flask_mail import Mail, Message
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models.User import User
from models.Forms import *
from database import *
from wrappers import *
from datetime import datetime
from routes.audit_logs import audit_logs, audit_logs_classification, mask_event, mask_user
from populate_data import *
import pandas as pd

# config app
app = Flask(__name__)
app.config['MYSQL_USER'] = 'root'  # Change to appropriate user
app.config['MYSQL_HOST'] = '127.0.0.1'  # Config to ur localhost
app.config['MYSQL_PORT'] = 3306  # Change to the appropriate port
app.config['MYSQL_PASSWORD'] = 'Xmg938grqvxsEs*'  # Your password here
app.config['MYSQL_DB'] = 'audit_manager'  # Change to appropriate database

# config flask session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

# initialize apps
mysql = MySQL(app)
login_manager = LoginManager()
login_manager.init_app(app)
Session(app)
mail = Mail(app)

# registered blueprints to app
app.register_blueprint(audit_logs)

# config app
app.config["SECRET_KEY"] = "SECRET_KEY"


@app.route('/')
def homepage():
    get_db()
    check_users()
    check_audit_logs()
    populate_user()
    # populate_audit_logs()
    return redirect(url_for('login'))


def get_db():
    conn = mysql.connection
    if conn.closed:
        conn.ping(reconnect=True)
    cursor = conn.cursor()
    return conn, cursor


@login_manager.user_loader
def load_user(user_id):
    check_users()
    conn, cursor = get_db()
    query = 'SELECT * FROM users_info WHERE user_ID=%s'
    cursor.execute(query, (int(user_id),))
    user_data = cursor.fetchone()
    if user_data:
        loaded_user = User(user_id=user_data[0], f_name=user_data[1], l_name=user_data[2], email=user_data[3],
                           password=user_id[4], profile_pic_path=user_data[5], role=user_data[6], salt=user_data[7])
        return loaded_user
    else:
        return None


@app.route('/login', methods=['POST', 'GET'])
def login():
    # check if user is authenticated & redirect to respective dashboard based on their role
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for('admin_dashboard'))
        elif current_user.is_auditor():
            return redirect(url_for('auditor_dashboard'))
        elif current_user.is_librarian():
            return redirect(url_for('librarian_dashboard'))

    login_form = LoginForm()
    if request.method == 'POST' and login_form.validate():
        email = login_form.email.data
        password = login_form.password.data

        conn, cursor = get_db()
        query = 'SELECT * FROM users_info WHERE email=%s'
        cursor.execute(query, (login_form.email.data,))
        user_data = cursor.fetchone()
        if user_data is None:
            flash('Invalid username/password!', 'danger')
            print("Login Unsuccessful!")
            return render_template('login.html', form=login_form)
        else:
            pw_check = login_form.password.data
            salt = user_data[7].encode()
            password_check = bcrypt.hashpw(pw_check.encode(), salt)
            if user_data and user_data[4] == password_check.decode():
                # set the data into User object
                loaded_user = load_user(str(user_data[0]))
                login_user(loaded_user)
                print("Login Successful!")
                print("Debug User:", current_user.get_role())

                # implement session
                session['logged_in'] = True
                print("Session implemented successfully!")

                # redirect based on User Role to dashboard
                if loaded_user.is_admin():
                    return redirect(url_for('admin_dashboard'))
                elif loaded_user.is_auditor():
                    return redirect(url_for('auditor_dashboard'))
                elif loaded_user.is_librarian():
                    return redirect(url_for('librarian_dashboard'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                flash('Invalid email/password!', 'danger')
                print("password wrong!")
            return render_template('login.html', form=login_form)
    else:
        return render_template('login.html', form=login_form)


@app.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated():
        fname = current_user.get_f_name()
        lname = current_user.get_l_name()
        print("User", fname, lname, "is logged out successfully!")

    logout_user()

    # clear session
    session.pop('logged_in', None)
    print("Session cleared successfully!")

    return redirect(url_for('homepage'))


@app.route('/admin_dashboard', methods=['GET'])
@login_required
@rbac_required(user_class='Admin')
def admin_dashboard():
    # get selected category from request
    selected_category = request.args.get('category', default=None)

    # establish MySQL connection
    conn = mysql.connection
    cursor = conn.cursor()

    # calculate timestamp for current day
    today = datetime.now()
    today = today.strftime("%d/%m/%Y")

    # retrieve audit logs for current day & selected category
    if selected_category:
        query = '''
        SELECT
                *
        FROM
            audit_logs
        WHERE
            DATE_FORMAT(STR_TO_DATE(timestamp, '%%d/%%m/%%Y, %%H:%%i:%%s'), '%%d/%%m/%%Y') = %s
        AND
            CATEGORY = %s
        ORDER BY
            STR_TO_DATE(timestamp, '%%d/%%m/%%Y, %%H:%%i:%%s') DESC
        '''
        cursor.execute(query, (today, selected_category))

    else:
        query = '''
        SELECT
                *
        FROM
            audit_logs
        WHERE
            DATE_FORMAT(STR_TO_DATE(timestamp, '%%d/%%m/%%Y, %%H:%%i:%%s'), '%%d/%%m/%%Y') = %s
        ORDER BY
            STR_TO_DATE(timestamp, '%%d/%%m/%%Y, %%H:%%i:%%s') DESC
        '''
        cursor.execute(query, (today,))

    # convert Firebase audit logs for the current day
    logs_data = cursor.fetchall()

    # check user roles against classification level of audit log
    user_role = current_user.get_role()
    logs_data = audit_logs_classification(logs_data, user_role)

    # # decode bytes objects to strings
    # decoded_logs = []
    # for log in logs_data:
    #     decoded_log = [value.decode('utf-8') if isinstance(value, bytes) else value for value in log]
    #     decoded_logs.append(decoded_log)

    # Convert logs into a DataFrame
    df = pd.DataFrame(logs_data,
                      columns=['audit_log_ID', 'timestamp', 'classification', 'action', 'category', 'event', 'role',
                               'user', 'status'])

    return render_template('admin_dashboard.html', logs=df.to_dict(orient='records'),
                           selected_category=selected_category)


@app.route('/auditor_dashboard')
@login_required
@rbac_required(user_class='Auditor')
def auditor_dashboard():
    # get selected category from request
    selected_category = request.args.get('category', default=None)

    # establish MySQL connection
    conn = mysql.connection
    cursor = conn.cursor()

    # calculate timestamp for current day
    today = datetime.now()
    today = today.strftime("%d/%m/%Y")

    # retrieve audit logs for current day & selected category
    if selected_category:
        query = '''
        SELECT
                *
        FROM
            audit_logs
        WHERE
            DATE_FORMAT(STR_TO_DATE(timestamp, '%%d/%%m/%%Y, %%H:%%i:%%s'), '%%d/%%m/%%Y') = %s
        AND
            CATEGORY = %s
        ORDER BY
            STR_TO_DATE(timestamp, '%%d/%%m/%%Y, %%H:%%i:%%s') DESC
        '''
        cursor.execute(query, (today, selected_category))

    else:
        query = '''
        SELECT
                *
        FROM
            audit_logs
        WHERE
            DATE_FORMAT(STR_TO_DATE(timestamp, '%%d/%%m/%%Y, %%H:%%i:%%s'), '%%d/%%m/%%Y') = %s
        ORDER BY
            STR_TO_DATE(timestamp, '%%d/%%m/%%Y, %%H:%%i:%%s') DESC
        '''
        cursor.execute(query, (today,))

    logs_data = cursor.fetchall()

    # data classification
    user_role = current_user.get_role()
    logs_data = audit_logs_classification(logs_data, user_role)

    # # decode bytes objects to strings
    # decoded_logs = []
    # for log in logs_data:
    #     decoded_log = [value.decode('utf-8') if isinstance(value, bytes) else value for value in log]
    #     decoded_logs.append(decoded_log)

    # Convert logs into a DataFrame
    df = pd.DataFrame(logs_data,
                      columns=['audit_log_ID', 'timestamp', 'classification', 'action', 'category', 'event', 'role',
                               'user', 'status'])

    # mask logs with classification 'Confidential' or 'Secret'
    masked_logs = df[df['classification'].isin(['Confidential', 'Secret'])].copy()

    # mask 'user' column
    masked_logs['user'] = masked_logs['user'].apply(mask_user)

    # mask 'event' column
    masked_logs['event'] = masked_logs['event'].apply(mask_event)

    # update original dataframe with masked values
    df.loc[masked_logs.index] = masked_logs

    return render_template('auditor_dashboard.html', logs=df.to_dict(orient='records'),
                           selected_category=selected_category)


@app.route('/librarian_dashboard')
@login_required
@rbac_required(user_class='Librarian')
def librarian_dashboard():
    # get selected category from request
    selected_category = request.args.get('category', default=None)

    # establish MySQL connection
    conn = mysql.connection
    cursor = conn.cursor()

    # calculate timestamp for current day
    today = datetime.now()
    today = today.strftime("%d/%m/%Y")

    # retrieve audit logs for current day & selected category
    if selected_category:
        query = '''
            SELECT
                *
        FROM
            audit_logs
            WHERE
                DATE_FORMAT(STR_TO_DATE(timestamp, '%%d/%%m/%%Y, %%H:%%i:%%s'), '%%d/%%m/%%Y') = %s
            AND
                CATEGORY = %s
            ORDER BY
                STR_TO_DATE(timestamp, '%%d/%%m/%%Y, %%H:%%i:%%s') DESC
            '''
        cursor.execute(query, (today, selected_category))

    else:
        query = '''
            SELECT
                *
        FROM
            audit_logs
            WHERE
                DATE_FORMAT(STR_TO_DATE(timestamp, '%%d/%%m/%%Y, %%H:%%i:%%s'), '%%d/%%m/%%Y') = %s
            ORDER BY
                STR_TO_DATE(timestamp, '%%d/%%m/%%Y, %%H:%%i:%%s') DESC
            '''
        cursor.execute(query, (today,))

    logs_data = cursor.fetchall()

    # data classification
    user_role = current_user.get_role()
    logs_data = audit_logs_classification(logs_data, user_role)

    # # decode bytes objects to strings
    # decoded_logs = []
    # for log in logs_data:
    #     decoded_log = [value.decode('utf-8') if isinstance(value, bytes) else value for value in log]
    #     decoded_logs.append(decoded_log)

    # Convert logs into a DataFrame
    df = pd.DataFrame(logs_data,
                      columns=['audit_log_ID', 'timestamp', 'classification', 'action', 'category', 'event', 'role',
                               'user', 'status'])

    # mask logs with classification 'Confidential' or 'Secret'
    masked_logs = df[df['classification'].isin(['Confidential', 'Secret'])].copy()

    # mask 'user' column
    masked_logs['user'] = masked_logs['user'].apply(mask_user)

    # mask 'event' column
    masked_logs['event'] = masked_logs['event'].apply(mask_event)

    # update original dataframe with masked values
    df.loc[masked_logs.index] = masked_logs

    return render_template('librarian_dashboard.html', logs=df.to_dict(orient='records'),
                           selected_category=selected_category)


@app.route('/user_management')
@login_required
@rbac_required(user_class='Admin')
def user_manager():
    print("Manage all users")

    conn, cursor = get_db()
    query = 'SELECT * FROM users_info'
    cursor.execute(query)
    rows = cursor.fetchall()
    print(rows)

    return render_template('user_management.html', rows=rows)


@app.route('/createUser', methods=['GET', 'POST'])
def create_user():
    create_user_form = CreateUser()

    if request.method == 'POST' and create_user_form.validate_on_submit():
        email = create_user_form.email.data
        f_name = create_user_form.f_name.data
        l_name = create_user_form.l_name.data
        pw = create_user_form.password.data
        salt = bcrypt.gensalt()
        encrypted_password = bcrypt.hashpw(pw.encode(), salt)
        profile_pic = create_user_form.profile_pic.data
        access_role = create_user_form.access_role.data
        user_id = gen_uuid()

        # saving product image
        image = profile_pic
        filename = image.filename
        print(filename)
        image.save('static/user_images/' + filename)

        profile_pic_path = ('static/user_images/' + filename,)


        # establish MySQL connection
        conn = mysql.connection
        cursor = conn.cursor()

        create_user_query = '''
                INSERT INTO users_info (user_ID, f_name, l_name, email, password, profile_pic_path, access_role, salt) VALUES
                (%s, %s, %s, %s, %s, %s, %s, %s) '''

        values = (user_id, f_name, l_name, email, encrypted_password, profile_pic_path, access_role, salt)
        cursor.execute(create_user_query, values)

        print("User created successfully!")

        conn.commit()
        cursor.close()

        return redirect(url_for('user_manager'))

    else:
        return render_template('create_user.html', form=create_user_form)


@app.route('/updateUser/<int:id>', methods=['GET', 'POST'])
@login_required
@rbac_required(user_class='Admin')
def update_user(id):
    update_user_form = UpdateUser()

    conn, cursor = get_db()

    # fetch existing user details from MySQL users_info table
    query = 'SELECT * FROM users_info WHERE user_ID=%s'
    cursor.execute(query, (id,))
    result = cursor.fetchone()

    # populate form fields with retrieved data
    update_user_form.process(data={
        'f_name': result[1],
        'l_name': result[2],
        'email': result[3],
        'profile_pic': result[5],
        'access_role': result[6],
    }, obj=None)

    if request.method == 'POST':
        # retrieve the form data
        f_name = request.form.get('f_name')
        l_name = request.form.get('l_name')
        email = request.form.get('email')
        profile_pic = request.form.get('profile_pic')
        access_role = request.form.get('access_role')

        # check if new profile picture is updated
        if 'profile_pic' in request.files:
            profile_pic = request.files['profile_pic']
            if profile_pic.filename != '':
                image = profile_pic.filename
                profile_pic.save('static/user_images/' + image)

                values = ('static/user_images/' + image)
                print(values)

                # update MySQL users_info table
                query = 'UPDATE users_info SET f_name=%s, l_name=%s, email=%s, profile_pic_path=%s, access_role=%s ' \
                        'WHERE user_ID=%s'
                cursor.execute(query, (f_name, l_name, email, values, access_role, id))
                conn.commit()
                print("User details updated!")
            else:
                # no new profile pic uploaded, retain existing URL path
                profile_pic = result[5]

                # update MySQL users_info table
                query = 'UPDATE users_info SET f_name=%s, l_name=%s, email=%s, access_role=%s ' \
                        'WHERE user_ID=%s'
                cursor.execute(query, (f_name, l_name, email, access_role, id))
                conn.commit()
                print("User details updated!")

        else:
            # no new profile pic uploaded, retain existing URL path
            profile_pic = result[5]

            # update MySQL users_info table
            query = 'UPDATE users_info SET f_name=%s, l_name=%s, email=%s, access_role=%s ' \
                    'WHERE user_ID=%s'
            cursor.execute(query, (f_name, l_name, email, access_role, id))
            conn.commit()
            print("User details updated!")

        return redirect(url_for('user_manager'))

    return render_template('updateUser.html', form=update_user_form, id=id)


@app.route('/deleteUser/<int:id>', methods=['POST'])
@login_required
@rbac_required(user_class='Admin')
def delete_user(id):
    # establish MySQL connection
    conn = mysql.connection
    cursor = conn.cursor()

    if request.method == "POST":
        query = '''
                DELETE FROM users_info
                WHERE user_ID = %s
                '''
        cursor.execute(query, (id,))
        conn.commit()
        print("User deleted successfully")

    return redirect(url_for('user_manager'))


if __name__ == '__main__':
    app.run(ssl_context=('resources/cert.pem', 'resources/key.pem'), debug=True)
