# Generated by Django 3.0.8 on 2020-07-31 06:10

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('MasterHanbok', '0002_auto_20200726_1325'),
    ]

    operations = [
        migrations.AlterModelTable(
            name='requestmodel',
            table='requestmodel',
        ),
        migrations.AlterModelTable(
            name='signupmodel',
            table='usermodel',
        ),
    ]
