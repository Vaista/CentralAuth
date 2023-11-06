from django.urls import path

from . import views

urlpatterns = [
    path("login/", views.login_request, name="login"),
    path("signup/", views.signup_request, name="signup"),
    path("authenticate_user/", views.authenticate_user, name="authenticate_user"),
    path("logout_user/", views.logout_user, name="logout_user"),
]
