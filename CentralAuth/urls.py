from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.admin_redirect, name='admin_redirect'),
    path('admin/', admin.site.urls),
    path('user_auth/', include('user_authentication.urls')),
]
