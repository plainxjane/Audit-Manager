from flask_login import UserMixin


class User(UserMixin):
    def __init__(self, user_id, f_name, l_name, email, password, profile_pic_path, role, salt):
        self.__user_id = user_id
        self.__f_name = f_name
        self.__l_name = l_name
        self.__email = email
        self.__password = password
        self.__salt = salt
        self.__profile_pic_path = profile_pic_path
        self.__role = role

    # getters & setters
    def get_id(self):
        return str(self.__user_id)

    def set_user_id(self, user_id):
        self.user_id = user_id

    def get_f_name(self):
        return self.__f_name

    def set_f_name(self, f_name):
        self.__f_name = f_name

    def get_l_name(self):
        return self.__l_name

    def set_l_name(self, l_name):
        self.__l_name = l_name

    def get_email(self):
        return self.__email

    def set_email(self, email):
        self.__email = email

    def get_password(self):
        return self.__password

    def set_password(self, password):
        self.__password = password

    def get_salt(self):
        return self.__salt

    def set_salt(self, salt):
        self.__salt = salt

    def get_profile_pic_path(self):
        return self.__profile_pic_path

    def set_profile_pic_path(self, profile_pic_path):
        self.__profile_pic_path = profile_pic_path

    def get_role(self):
        return self.__role

    def set_role(self, role):
        self.__role = role

    def is_authenticated(self):
        return True

    def is_admin(self):
        return self.__role == 'Admin'

    def is_auditor(self):
        return self.__role == 'Auditor'

    def is_librarian(self):
        return self.__role == 'Librarian'
