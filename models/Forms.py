from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, IntegerField, FloatField, FileField, DateField, \
    SubmitField, EmailField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Length, Optional,ValidationError
from wtforms import validators


class LoginForm(FlaskForm):
    email = EmailField('Email')
    password = PasswordField('Password')
    submit = SubmitField('Submit')


class CreateUser(FlaskForm):
    email = EmailField('Email')
    f_name = StringField('First Name')
    l_name = StringField('Last Name')
    password = PasswordField('Password')
    profile_pic = FileField('Upload Profile Image')
    access_role = SelectField('Access Role', choices=[('Admin', 'Admin'),
                                                      ('Auditor', 'Auditor'),
                                                      ('Librarian', 'Librarian')])
    submit = SubmitField('Submit')


class UpdateUser(FlaskForm):
    f_name = StringField('First Name')
    l_name = StringField('Last Name')
    email = EmailField('Email')
    profile_pic = FileField('Upload Profile Image')
    access_role = SelectField('Access Role', choices=[('Admin', 'Admin'),
                                                      ('Auditor', 'Auditor'),
                                                      ('Librarian', 'Librarian')])
    submit = SubmitField('Submit')


class ResolveLogForm(FlaskForm):
    investigated_no_action = BooleanField('Investigated and No Action Required')
    escalate_to_management = BooleanField('Escalate to Management')
    mitigation_implemented = BooleanField('Mitigation Implemented')
    follow_up_required = BooleanField('Follow Up Required')
    issue_resolved = BooleanField('Issue Resolved')

    submit = SubmitField('Resolve')


class RequestAccessForm(FlaskForm):
    password = PasswordField('Password: ')

    submit = SubmitField('Submit')
