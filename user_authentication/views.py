from django.http import JsonResponse
from django.conf import settings
import jwt


def login_request(request):
    """Validated the login request coming from outside apps"""

    token = request.GET.get('data')
    if not token:
        return JsonResponse({'data': {'status': 'error', 'reason': 'token not provided'}}, status=400)
    data = jwt.decode(token, settings.PROJECT_SECRET, algorithms=["HS256"])

    return JsonResponse({'status': 'ok'})


def signup_request(request):
    """Validated the Signup request coming from outside apps and sign user in"""

    token = request.GET.get('data')

    if not token:
        return JsonResponse({'data': {'status': 'error', 'reason': 'token not provided'}}, status=400)
    data = jwt.decode(token, settings.PROJECT_SECRET, algorithms=["HS256"])
    print(data)

    return JsonResponse({'status': 'ok'})
