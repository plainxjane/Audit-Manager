import uuid, bcrypt
from flask import Flask
from flask_mysqldb import MySQL
from datetime import datetime

app = Flask(__name__)
app.config['MYSQL_USER'] = 'root'  # Change to appropriate user
app.config['MYSQL_HOST'] = '127.0.0.1'  # Config to ur localhost
app.config['MYSQL_PORT'] = 3306  # Change to the appropriate port
app.config['MYSQL_PASSWORD'] = 'Xmg938grqvxsEs*'  # Ur password here
app.config['MYSQL_DB'] = 'audit_manager'  # Change to appropriate database
mysql = MySQL(app)


def gen_uuid():
    uuid_id = uuid.uuid4().int & (1 << 32) - 1
    print("uuid:", uuid_id)
    return uuid_id


def timestamp():
    now = datetime.now()  # current date & time
    time_stamp = now.strftime("%d/%m/%Y, %H:%M:%S")
    print(time_stamp)
    return time_stamp


def populate_user():
    # establish MySQL connection
    conn = mysql.connection
    cursor = conn.cursor()
    print("Connection established.")

    # check if user already exists
    email = 'janeheng@gmail.com'
    check_user_query = '''
                        SELECT COUNT(*)
                        FROM users_info
                        WHERE email = %s
                        '''
    cursor.execute(check_user_query, (email,))
    user_count = cursor.fetchone()[0]

    if user_count == 0:

        # generate login info
        admin_user_id = gen_uuid()
        salt = bcrypt.gensalt()
        pw = 'password'
        encrypted_password = bcrypt.hashpw(pw.encode(), salt)


        create_user_query = '''
            INSERT INTO users_info (user_ID, f_name, l_name, email, password, profile_pic_path, access_role, salt) VALUES
            (%s, %s, %s, %s, %s, %s, %s, %s) '''

        test_admin = (admin_user_id, 'Jane', 'Heng', 'janeheng@gmail.com', encrypted_password, 'no/profile', 'Admin', salt)

        cursor.execute(create_user_query, test_admin)
        print("Admin created!")

        conn.commit()

    else:
        print("User already exists")


def populate_audit_logs():
    # establish MySQL connection
    conn = mysql.connection
    cursor = conn.cursor()
    print("Connection established.")

    num_entries = 1

    # loop to populate audit logs
    for i in range(num_entries):
        log_id = gen_uuid()
        print(log_id)
        now = datetime.now()
        timestamp = now.strftime("%d/%m/%Y, %H:%M:%S")

        # change status to 'Processing' or 'Clear'
        status = 'Processing'

        create_audit_query = '''
        INSERT INTO audit_logs (audit_log_ID, timestamp, classification, action, category, event, role, user, status) VALUES
        (%s, %s, %s, %s, %s, %s, %s, %s, %s) '''

        # change the classification/action/category/event/role/user to populate your audit logs accordingly
        test_log = (log_id, timestamp, 'Secret', 'Unauthorized Access', 'Authentication',
                    'System detected unauthorized access to Admin Dashboard',
                    'Auditor', 'Jeremy White', status)

        # execute
        cursor.execute(create_audit_query, test_log)
        conn.commit()
        print("Audit logs populated successfully")
