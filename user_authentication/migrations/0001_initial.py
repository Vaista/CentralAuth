# Generated by Django 4.2.6 on 2023-10-31 11:15

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import user_authentication.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('email', models.EmailField(max_length=254, unique=True, verbose_name='Email Address')),
                ('first_name', models.CharField(max_length=30, verbose_name='first Name')),
                ('last_name', models.CharField(max_length=30, verbose_name='Last Name')),
                ('password', models.CharField(max_length=256, verbose_name='Password')),
                ('valid_token', models.CharField(max_length=255, unique=True)),
                ('token_expiration', models.DateTimeField()),
                ('created_on', models.DateTimeField(default=django.utils.timezone.now)),
                ('active', models.BooleanField(default=True, verbose_name='Active')),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
            },
            managers=[
                ('objects', user_authentication.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='App',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50, unique=True)),
                ('key', models.CharField(max_length=256, unique=True)),
                ('active', models.BooleanField(default=True)),
            ],
        ),
        migrations.CreateModel(
            name='UserAppAccess',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('valid_token', models.CharField(max_length=255)),
                ('token_expiration', models.DateTimeField()),
                ('first_access', models.DateTimeField(default=django.utils.timezone.now, verbose_name='Access Since')),
                ('last_access', models.DateTimeField(verbose_name='Last Activity')),
                ('logged_in', models.BooleanField(default=False, verbose_name='Logged In')),
                ('active', models.BooleanField(default=True, verbose_name='Active')),
                ('app', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='user_authentication.app')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
