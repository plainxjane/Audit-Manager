from flask import Flask, render_template, request, redirect, url_for, Blueprint, session
from flask_mysqldb import MySQL
from flask_mail import Mail, Message
from wrappers import *
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from faker import Faker
from models.Forms import *
import pandas as pd
import re
import matplotlib.pyplot as plt

# configure Flask app
app = Flask(__name__)
app.config['MYSQL_USER'] = 'root'  # Change to appropriate user
app.config['MYSQL_HOST'] = '127.0.0.1'  # Config to ur localhost
app.config['MYSQL_PORT'] = 3306  # Change to the appropriate port
app.config['MYSQL_PASSWORD'] = 'Xmg938grqvxsEs*'  # Ur password here
app.config['MYSQL_DB'] = 'audit_manager'  # Change to appropriate database

# initialize apps
mysql = MySQL(app)
login_manager = LoginManager()
login_manager.init_app(app)

# config app
app.config["SECRET_KEY"] = "SECRET_KEY"

# route
audit_logs = Blueprint('audit_logs', __name__)


@audit_logs.route('/audit_logs', methods=['GET'])
@login_required
def logs():
    # get selected category from request
    selected_category = request.args.get('category', default=None)

    # establish MySQL connection
    conn = mysql.connection
    cursor = conn.cursor()

    if selected_category:
        query = '''
                SELECT
                   *
                FROM
                    audit_logs
                WHERE
                    CATEGORY = %s
                ORDER BY
                    STR_TO_DATE(timestamp, %s) DESC
                '''

        cursor.execute(query, (selected_category, '%d/%m/%Y, %H:%i:%s'))

    else:
        query = '''
                SELECT
                    *
                FROM
                    audit_logs
                ORDER BY
                    STR_TO_DATE(timestamp, %s) DESC
                '''

        cursor.execute(query, ('%d/%m/%Y, %H:%i:%s',))

    # fetch logs
    all_logs = cursor.fetchall()

    # check user roles against classification level of audit log
    user_role = current_user.get_role()
    filtered_logs = audit_logs_classification(all_logs, user_role)

    # Convert logs into a DataFrame
    df = pd.DataFrame(filtered_logs,
                      columns=['audit_log_ID', 'timestamp', 'classification', 'action', 'category', 'event', 'role',
                               'user', 'status'])

    # mask for only 'Librarian' and 'Auditor' role
    if user_role in ['Auditor', 'Librarian']:
        masked_logs = df[df['classification'].isin(['Confidential', 'Secret'])].copy()

        # mask 'user' column
        masked_logs['user'] = masked_logs['user'].apply(mask_user)

        # mask 'event' column
        masked_logs['event'] = masked_logs['event'].apply(mask_event)

        # update original dataframe with masked values
        df.loc[masked_logs.index] = masked_logs

    return render_template('audit_logs.html', logs=df.to_dict(orient='records'), selected_category=selected_category)


def audit_logs_classification(logs, user_role):
    role_classification_mapping = {
        'Admin': ['Internal', 'Confidential', 'Secret'],
        'Auditor': ['Internal', 'Confidential', 'Secret'],
        'Librarian': ['Internal'],
    }

    allowed_classifications = role_classification_mapping.get(user_role, [])

    filtered_logs = [log for log in logs if log[2] in allowed_classifications]

    return filtered_logs


def mask_event(event):
    patterns = [
        r'Borrowed .*? of (.*)$',
        r'Accessed restricted API endpoint for (.*)$',
        r'Viewed .*? of (.*)$',
        r'Reset .*? of (.*)$',
        r'Exported sensitive .*? of user (.*)$',
        r'System detected unauthorized access to (.*)$',
        r'Configured system settings by updating (.*)$',
        r'Granted (.*?) with .*?$',
        r'Modified .*? to restrict (.*)$',
        r'Modified .*? to grant (.*)$'
    ]

    for pattern in patterns:
        match = re.search(pattern, event)
        if match:
            # extract the substring of title
            data_to_mask = match.group(1)

            # mask the data
            masked_data = '*' * 5

            # replace the extracted substring with masked data in the event text
            masked_event = event.replace(data_to_mask, masked_data)

            return masked_event

    return event


def mask_user(user):
    fake = Faker()
    return fake.name()


@audit_logs.route('/resolve/<int:id>/', methods=['GET', 'POST'])
@login_required
@rbac_required(user_class='Admin')
def resolve(id):
    # establish MYSQL connection
    conn = mysql.connection
    cursor = conn.cursor()

    query = '''
            SELECT
               *
            FROM audit_logs
            WHERE audit_log_ID = %s
    '''
    cursor.execute(query, (id,))
    log = cursor.fetchone()
    print("Log to be resolved:", log[2])

    resolve_log_form = ResolveLogForm()

    if request.method == 'POST' and resolve_log_form.validate_on_submit():
        # retrieve the form data
        investigated_no_action = resolve_log_form.investigated_no_action.data
        escalate_to_management = resolve_log_form.escalate_to_management.data
        mitigation_implemented = resolve_log_form.mitigation_implemented.data
        follow_up_required = resolve_log_form.follow_up_required.data
        issue_resolved = resolve_log_form.issue_resolved.data

        status = 'Clear'

        # update MySQL table
        query = '''
                UPDATE audit_logs
                SET status = %s
                WHERE audit_log_ID = %s
                '''

        cursor.execute(query, (status, id))
        conn.commit()

        return redirect(url_for('audit_logs.logs'))

    else:
        return render_template('resolve.html', log=log, form=resolve_log_form)


@audit_logs.route('/analytics')
@login_required
def analytics():
    # establish mysql connection
    conn = mysql.connection
    cursor = conn.cursor()

    # fetch audit logs
    query = '''
            SELECT
                category, status, role
            FROM
            audit_logs
            '''

    cursor.execute(query)
    all_logs = cursor.fetchall()

    # extract categories, statuses & roles
    categories = [log[0] for log in all_logs]
    statuses = [log[1] for log in all_logs]

    # generate bar graph for categories
    category_counts = {}
    for category in categories:
        category_counts[category] = category_counts.get(category, 0) + 1

    plt.bar(category_counts.keys(), category_counts.values())
    plt.title('Audit Log Categories')
    plt.xlabel('Category')
    plt.ylabel('No. of audit logs')
    plt.xticks(rotation=45)

    # add no. of logs for each bar(category)
    for category, count in category_counts.items():
        plt.text(category, count, str(count), ha='center', va='bottom')

    plt.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.3)  # Adjust the padding as needed
    plt.tight_layout()
    plt.savefig('static/category_bar_chart.png')
    plt.close()

    # generate pie chart for statuses
    status_counts = {}
    for status in statuses:
        status_counts[status] = status_counts.get(status, 0) + 1

    # prepare labels with status & count
    labels = [f"{status} ({count})" for status, count in status_counts.items()]

    plt.pie(status_counts.values(), labels=labels, autopct='%1.1f%%')
    plt.title('Audit Log Status')
    plt.tight_layout()
    plt.savefig('static/status_pie_chart.png')
    plt.close()

    return render_template('analytics.html')


@audit_logs.route('/request_access', methods=['GET', 'POST'])
@login_required
def request_access():
    request_access_form = RequestAccessForm()
    assigned_password = 'Xmg938grqvxsEs*'

    if request.method == 'POST' and request_access_form.validate_on_submit():
        entered_password = request_access_form.password.data

        if entered_password == assigned_password:
            return redirect(url_for('audit_logs.unmasked_logs'))

        else:
            print("Password wrong.")

    return render_template('request_access.html', form=request_access_form)


@audit_logs.route('/unmasked_logs')
@login_required
@rbac_required(user_class='Auditor')
def unmasked_logs():
    # establish mysql connection
    conn = mysql.connection
    cursor = conn.cursor()

    query = '''
            SELECT
                *
            FROM
                audit_logs
            ORDER BY 
                STR_TO_DATE(timestamp, %s) DESC
    '''
    cursor.execute(query, ('%d/%m/%Y, %H:%i:%s',))
    logs = cursor.fetchall()

    return render_template('unmasked_logs.html', logs=logs)