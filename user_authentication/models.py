from django.db import models
from django.utils import timezone


class User(models.Model):
    """Model for Custom User Account"""
    first_name = models.CharField('First Name', max_length=50)
    last_name = models.CharField('Last Name', max_length=50)
    email = models.EmailField('Email', max_length=50, unique=True)
    password = models.CharField('Password', max_length=256)
    created_on = models.DateTimeField(default=timezone.now)
    active = models.BooleanField(default=True)

    def __str__(self):
        return f'{self.first_name} {self.last_name}'


class App(models.Model):
    """Model for applications"""
    name = models.CharField(max_length=50, unique=True)
    key = models.CharField(max_length=256, blank=False)
    active = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class UserAppAccess(models.Model):
    """Model for User access to different apps"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    app = models.ForeignKey(App, on_delete=models.CASCADE)
    valid_token = models.CharField(max_length=255)
    token_expiration = models.DateTimeField()
    first_access = models.DateTimeField('Access Since', default=timezone.now)
    last_access = models.DateTimeField('Last Activity')
    logged_in = models.BooleanField('Logged In', default=False)
    active = models.BooleanField('Active', default=True)

    def __str__(self):
        return f'{self.user} - {self.app}'
