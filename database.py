from flask import Flask
from flask_mysqldb import MySQL

app = Flask(__name__)
app.config['MYSQL_USER'] = 'root'  # Change to appropriate user
app.config['MYSQL_HOST'] = '127.0.0.1'  # Config to ur localhost
app.config['MYSQL_PORT'] = 3306  # Change to the appropriate port
app.config['MYSQL_PASSWORD'] = 'Xmg938grqvxsEs*'  # Ur password here
app.config['MYSQL_DB'] = 'audit_manager'  # Change to appropriate database

mysql = MySQL(app)


def check_users():
    # establish MySQL connection
    conn = mysql.connection
    cursor = conn.cursor()
    print("Connection established.")
    # Retrieve all exising tables
    cursor.execute("SHOW TABLES;")
    existing_tables = [row[0] for row in cursor.fetchall()]
    # check if users_info table exist in database
    if 'users_info' not in existing_tables:
        create_table_query = '''
        Create table users_info (
        user_ID BIGINT PRIMARY KEY UNIQUE,
        f_name VARCHAR(75) NOT NULL,
        l_name VARCHAR(75) NOT NULL,
        email VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL,
        profile_pic_path VARCHAR(512) NOT NULL,
        access_role VARCHAR(70) NOT NULL,
        salt VARCHAR(255) NOT NULL
        )
        '''
        # execute database query
        cursor.execute(create_table_query)
        conn.commit()
        test_message = "Query to create Users table executed successfully"
        print(test_message)
    else:
        test_message = "Query not executed. Users table already exists"
        print(test_message)

    return test_message


def check_audit_logs():
    # establish MySQL connection
    conn = mysql.connection
    cursor = conn.cursor()
    print("Connection established.")
    # Retrieve all exising tables
    cursor.execute("SHOW TABLES;")
    existing_tables = [row[0] for row in cursor.fetchall()]

    # check if audit_logs table exist in database
    if 'audit_logs' not in existing_tables:
        create_table_query = '''
            Create table audit_logs (
            audit_log_ID BIGINT PRIMARY KEY UNIQUE,
            timestamp VARCHAR(255) NOT NULL,
            classification VARCHAR(75) NOT NULL,
            action VARCHAR(255) NOT NULL,
            category VARCHAR(255) NOT NULL,
            event VARCHAR (512) NOT NULL,
            role VARCHAR (255) NOT NULL,
            user VARCHAR(255) NOT NULL,
            status VARCHAR(255) NOT NULL
            )
            '''
        # execute database query
        cursor.execute(create_table_query)
        conn.commit()
        test_message = "Query to create Audit Logs table executed successfully"
        print(test_message)
    else:
        test_message = "Query not executed. Audit Logs table already exists"
        print(test_message)

    return test_message


