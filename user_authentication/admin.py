from django.contrib.auth.models import Group, User
from django.contrib import admin
from .models import User as Users, App, UserAppAccess


admin.site.unregister(User)
admin.site.unregister(Group)


@admin.register(Users)
class UserAdmin(admin.ModelAdmin):
    list_display = ['first_name', 'last_name', 'email', 'active', 'created_on']


@admin.register(App)
class AppAdmin(admin.ModelAdmin):
    list_display = ['name', 'active']


@admin.register(UserAppAccess)
class UserAppAccessAdmin(admin.ModelAdmin):
    list_display = ['user', 'app', 'first_access', 'last_access', 'token_expiration',
                    'logged_in', 'active']
