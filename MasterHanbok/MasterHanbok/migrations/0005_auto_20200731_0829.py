# Generated by Django 3.0.8 on 2020-07-31 08:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('MasterHanbok', '0004_auto_20200731_0820'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bidders',
            name='store_image',
            field=models.CharField(blank=True, max_length=500),
        ),
    ]
