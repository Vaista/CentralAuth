# Generated by Django 4.2.6 on 2023-10-31 11:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user_authentication', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_staff',
            field=models.BooleanField(default=False),
        ),
    ]