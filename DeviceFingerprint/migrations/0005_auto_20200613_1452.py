# Generated by Django 3.0.3 on 2020-06-13 14:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('DeviceFingerprint', '0004_auto_20200606_1547'),
    ]

    operations = [
        migrations.AlterField(
            model_name='packetdata',
            name='packet_time',
            field=models.DecimalField(decimal_places=16, default=0.0, max_digits=16),
        ),
    ]
