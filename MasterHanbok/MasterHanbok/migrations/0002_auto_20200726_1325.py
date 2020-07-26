# Generated by Django 3.0.7 on 2020-07-26 13:25

import django.contrib.postgres.fields
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('MasterHanbok', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Bidders',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('store_name', models.CharField(max_length=15)),
                ('phone_num', models.CharField(max_length=15)),
                ('location', models.CharField(max_length=70)),
                ('store_image', models.CharField(max_length=70)),
                ('introduce', models.CharField(max_length=70)),
            ],
            options={
                'db_table': 'bidder',
            },
        ),
        migrations.CreateModel(
            name='DetailBiddingModel',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('price_and_discount', models.CharField(max_length=15)),
                ('service_product', models.CharField(max_length=30)),
                ('design', models.CharField(max_length=30)),
                ('design_images', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(default='', max_length=70), size=None)),
                ('color', models.CharField(max_length=30)),
                ('color_images', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(default='', max_length=70), size=None)),
                ('detail', models.CharField(max_length=70)),
                ('detail_images', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(default='', max_length=70), size=None)),
                ('note', models.CharField(max_length=70)),
                ('note_images', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(default='', max_length=70), size=None)),
            ],
            options={
                'db_table': 'detail_bid',
            },
        ),
        migrations.AddField(
            model_name='requestmodel',
            name='ended_or_not',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='signupmodel',
            name='nickname',
            field=models.CharField(default='', max_length=40),
        ),
        migrations.CreateModel(
            name='BiddingModel',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('price', models.CharField(max_length=30)),
                ('bidder', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='MasterHanbok.Bidders')),
                ('detail_bidding', models.OneToOneField(null=True, on_delete=django.db.models.deletion.SET_NULL, to='MasterHanbok.DetailBiddingModel')),
                ('request', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='MasterHanbok.RequestModel')),
            ],
            options={
                'db_table': 'bid',
            },
        ),
    ]
