# Generated by Django 3.0.3 on 2020-06-06 15:47

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('DeviceFingerprint', '0003_packetdata_field_name'),
    ]

    operations = [
        migrations.RenameField(
            model_name='packetdata',
            old_name='field_name',
            new_name='arrival_time',
        ),
    ]
