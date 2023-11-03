import re
import jwt
from django.conf import settings


def valid_email(email):
    regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')

    if re.fullmatch(regex, email):
        return True
    return False


def valid_password(password):
    """Checks if the password provided is valid or not"""

    # Check if the password is at least 8 characters long
    if len(password) < 8:
        return False

    # Check if the password contains at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False

    # Check if the password contains at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False

    # Check if the password contains at least one digit
    if not re.search(r'[0-9]', password):
        return False

    # Check if the password contains at least one special character
    if not re.search(r'[!@#$%^&*()_+{}\[\]:;<>,.?~\\]', password):
        return False

    # If all criteria are met, the password is valid
    return True


def decode_jwt(incoming_token=None):
    """Accepts token and returns the decoded data"""
    # Get JWT Token
    token = incoming_token
    if not token:
        # If token is missing
        return None
    # Decode the JWT Token with Project Secret Key
    data = jwt.decode(token, settings.PROJECT_SECRET, algorithms=["HS256"])
    return data
