# Generated by Django 3.0.8 on 2020-08-04 09:08

import django.contrib.postgres.fields
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('MasterHanbok', '0006_auto_20200731_0833'),
    ]

    operations = [
        migrations.AlterField(
            model_name='biddingmodel',
            name='bidder',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='bidder', to='MasterHanbok.Bidders'),
        ),
        migrations.AlterField(
            model_name='detailbiddingmodel',
            name='color',
            field=models.CharField(max_length=2000),
        ),
        migrations.AlterField(
            model_name='detailbiddingmodel',
            name='color_images',
            field=django.contrib.postgres.fields.ArrayField(base_field=models.CharField(default='', max_length=3000), size=None),
        ),
        migrations.AlterField(
            model_name='detailbiddingmodel',
            name='design',
            field=models.CharField(max_length=2000),
        ),
        migrations.AlterField(
            model_name='detailbiddingmodel',
            name='design_images',
            field=django.contrib.postgres.fields.ArrayField(base_field=models.CharField(default='', max_length=3000), size=None),
        ),
        migrations.AlterField(
            model_name='detailbiddingmodel',
            name='detail',
            field=models.CharField(max_length=2000),
        ),
        migrations.AlterField(
            model_name='detailbiddingmodel',
            name='detail_images',
            field=django.contrib.postgres.fields.ArrayField(base_field=models.CharField(default='', max_length=3000), size=None),
        ),
        migrations.AlterField(
            model_name='detailbiddingmodel',
            name='note',
            field=models.CharField(max_length=2000),
        ),
        migrations.AlterField(
            model_name='detailbiddingmodel',
            name='note_images',
            field=django.contrib.postgres.fields.ArrayField(base_field=models.CharField(default='', max_length=3000), size=None),
        ),
        migrations.AlterField(
            model_name='detailbiddingmodel',
            name='price_and_discount',
            field=models.CharField(max_length=1000),
        ),
        migrations.AlterField(
            model_name='detailbiddingmodel',
            name='service_product',
            field=models.CharField(max_length=2000),
        ),
    ]