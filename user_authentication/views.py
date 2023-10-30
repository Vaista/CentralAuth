from django.http import JsonResponse
from django.conf import settings
from django.utils import timezone
from .helper import valid_email, valid_password
from user_authentication.models import User, App, UserAppAccess
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import jwt
import secrets


ph = PasswordHasher()


def login_request(request):
    """Validated the login request coming from outside apps"""

    token = request.GET.get('data')
    if not token:
        return JsonResponse({'data': {'status': 'error', 'reason': 'token not provided'}}, status=400)
    data = jwt.decode(token, settings.PROJECT_SECRET, algorithms=["HS256"])

    email = data.get('email')
    password = data.get('password')
    app_token = data.get('app_token')

    if app_token is None:
        return JsonResponse({'data': {'status': 'error', 'reason': 'token is missing'}}, status=400)

    if email is None:
        return JsonResponse({'data': {'status': 'error', 'reason': 'email missing'}}, status=400)

    if password is None:
        return JsonResponse({'data': {'status': 'error', 'reason': 'password missing'}}, status=400)

    user = User.objects.filter(email=email).first()
    if user is None:
        return JsonResponse({'data': {'status': 'error', 'reason': 'user account not created'}}, status=400)
    if user.active is False:
        return JsonResponse({'data': {'status': 'error', 'reason': 'user account inactive'}}, status=400)

    # Fetch App Object
    app = App.objects.filter(key=app_token).first()
    if app is None:
        return JsonResponse({'data': {'status': 'error', 'reason': 'invalid app token'}}, status=400)
    if app.active is False:
        return JsonResponse({'data': {'status': 'error', 'reason': 'app inactive'}}, status=400)

    user_app_access = UserAppAccess.objects.filter(user=user, app=app).first()
    if user_app_access is None:
        return JsonResponse({'data': {'status': 'error', 'reason': 'user account not created'}}, status=400)

    if user_app_access.active is True:

        try:
            ph.verify(user.password, password)
            if ph.check_needs_rehash(user.password):
                user.password = ph.hash(password)
                user.save()
        except VerifyMismatchError:
            return JsonResponse({'data': {'status': 'error', 'reason': 'incorrect password'}}, status=400)

        return JsonResponse({'status': 'ok'})
    else:
        return JsonResponse({'data': {'status': 'error', 'reason': 'access revoked'}}, status=400)


def signup_request(request):
    """Validated the Signup request coming from outside apps and sign user in"""

    # Get JWT Token from the incoming request
    token = request.GET.get('data')

    if not token:
        # If token is missing
        return JsonResponse({'data': {'status': 'error', 'reason': 'token not provided'}}, status=400)
    # Decode the JWT Token with Project Secret Key
    data = jwt.decode(token, settings.PROJECT_SECRET, algorithms=["HS256"])

    # Get request parameters
    first_name = data.get('first_name').strip().title()
    last_name = data.get('last_name').strip().title()
    email = data.get('email').strip().lower()
    password = data.get('password').strip()
    app_token = data.get('app_token').strip()

    # Validation
    if app_token is None:
        return JsonResponse({'data': {'status': 'error', 'reason': 'app token missing'}}, status=400)

    # Fetch App Object
    app = App.objects.filter(key=app_token).first()
    if app is None:
        return JsonResponse({'data': {'status': 'error', 'reason': 'invalid app token'}}, status=400)

    if first_name is None:
        return JsonResponse({'data': {'status': 'error', 'reason': 'first name missing'}}, status=400)

    if last_name is None:
        return JsonResponse({'data': {'status': 'error', 'reason': 'last name missing'}}, status=400)

    if email is None:
        return JsonResponse({'data': {'status': 'error', 'reason': 'email missing'}}, status=400)

    if password is None:
        return JsonResponse({'data': {'status': 'error', 'reason': 'password missing'}}, status=400)

    if not valid_email(email):
        return JsonResponse({'data': {'status': 'error', 'error': 'invalid email'}}, status=400)

    if not valid_password(password):
        return JsonResponse({'data': {'status': 'error', 'error': 'invalid password'}}, status=400)

    user = User.objects.filter(email=email).first()
    if user is not None:
        user_app_access = UserAppAccess.objects.filter(
            user=user,
            app=app
        ).first()
        if user_app_access is not None:
            return JsonResponse({'data': {'status': 'error', 'error': 'account already exists'}}, status=400)
    else:
        # Generate Hashed Password with Argon 2
        p_hash = ph.hash(password=password)

        # Save to database
        user = User.objects.create(first_name=first_name, last_name=last_name, email=email, password=p_hash)
        user.save()

        used_tokens = [x.valid_token for x in UserAppAccess.objects.all()]
        valid_token = secrets.token_hex(64)
        while valid_token in used_tokens:
            valid_token = secrets.token_hex(64)
        token_expiration = timezone.now() + timezone.timedelta(minutes=15)

        # Create a UserAppAccess instance to assign the app to the user
        user_app_access = UserAppAccess.objects.create(
            user=user,
            app=app,
            valid_token=valid_token,
            token_expiration=token_expiration,
            first_access=timezone.now(),
            last_access=timezone.now(),
            logged_in=True,
            active=True
        )
        user_app_access.save()

        return JsonResponse({'data': {'status': 'ok', }}, status=200)
