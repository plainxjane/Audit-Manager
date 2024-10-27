from flask import Flask
from flask_mysqldb import MySQL
import matplotlib.pyplot as plt
from collections import Counter
from io import BytesIO
import base64
from flask import send_file

# config app
app = Flask(__name__)
app.config['MYSQL_USER'] = 'root'  # Change to appropriate user
app.config['MYSQL_HOST'] = '127.0.0.1'  # Config to ur localhost
app.config['MYSQL_PORT'] = 3306  # Change to the appropriate port
app.config['MYSQL_PASSWORD'] = 'Xmg938grqvxsEs*'  # Ur password here
app.config['MYSQL_DB'] = 'audit_manager'  # Change to appropriate database
mysql = MySQL(app)


def generate_pie_chart(logs):
    # extract categories from logs
    categories = [log[4] for log in logs]

    # count no. of logs
    category_counts = Counter(categories)

    # plot pie chart
    plt.figure(figsize=(8,6))
    plt.pie(category_counts.values(), labels=category_counts.keys(),autopct='%1.1f%%', startangle=140)
    plt.axis('equal') # equal aspect ratio so pie is drawn as a circle
    plt.title('Audit Logs by Category')
    plt.show()
    print("Pie chart generated successfully!")

    # convert plot to a PNG image
    image = BytesIO()
    plt.savefig(image, format='png')
    image.seek(0)

    # encode the PNG image to base64 string
    image_base64 = base64.b64encode(image.getvalue()).decode('utf-8')
    plt.close()

    return image_base64

