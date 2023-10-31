from django.db import models
from django.core.mail import send_mail
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.base_user import BaseUserManager
from django.utils import timezone
import secrets


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """
        Creates and saves a User with the given email and password.
        """
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)

        used_tokens = [x.valid_token for x in UserAppAccess.objects.all()]
        valid_token = secrets.token_hex(32)
        while valid_token in used_tokens:
            valid_token = secrets.token_hex(32)

        user.valid_token = valid_token
        user.token_expiration = timezone.now() + timezone.timedelta(minutes=15)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_staff', True)

        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField('Email Address', unique=True)
    first_name = models.CharField('first Name', max_length=30)
    last_name = models.CharField('Last Name', max_length=30)
    password = models.CharField('Password', max_length=256)
    valid_token = models.CharField(max_length=255, unique=True)
    token_expiration = models.DateTimeField()
    created_on = models.DateTimeField(default=timezone.now)
    active = models.BooleanField('Active', default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'password']

    def __str__(self):
        return f'{self.first_name} {self.last_name}'

    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'

    def get_full_name(self):
        """Returns the first_name plus the last_name, with a space in between."""
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        """Returns the short name for the user."""
        return self.first_name

    def email_user(self, subject, message, from_email=None, **kwargs):
        """Sends an email to this User."""
        send_mail(subject, message, from_email, [self.email], **kwargs)


class App(models.Model):
    """Model for applications"""
    name = models.CharField(max_length=50, unique=True)
    key = models.CharField(max_length=256, blank=False, unique=True)
    active = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class UserAppAccess(models.Model):
    """Model for User access to different apps"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    app = models.ForeignKey(App, on_delete=models.CASCADE)
    first_access = models.DateTimeField('Access Since', default=timezone.now)
    last_access = models.DateTimeField('Last Activity')
    active = models.BooleanField('Active', default=True)

    def __str__(self):
        return f'{self.user} - {self.app}'
