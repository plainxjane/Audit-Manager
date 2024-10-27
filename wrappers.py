from functools import wraps
from flask import abort
from flask_login import current_user


def rbac_required(user_class=None):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            # allow access for unauthenticated users to public views
            if not current_user.is_authenticated:
                if user_class is None or user_class == 'Public':
                    return view_func(*args, **kwargs)
                else:
                    return abort(401)  # for unauthorized access to pages requiring Roles

            # check RBAC logic based on user's role
            user_role = current_user.get_role()

            # allow access for Admins to Admin pages
            if user_class == 'Admin':
                if current_user.is_authenticated and user_role == 'Admin':
                    return view_func(*args, **kwargs)
                else:
                    return abort(403)

            if user_class == 'Auditor':
                if current_user.is_authenticated and user_role in ['Auditor']:
                    return view_func(*args, **kwargs)
                else:
                    return abort(403)

            if user_class == 'Librarian':
                if current_user.is_authenticated and user_role in ['Librarian']:
                    return view_func(*args, **kwargs)
                else:
                    return abort(403)

        return wrapper

    return decorator

