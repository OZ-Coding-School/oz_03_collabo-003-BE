# Generated by Django 5.1 on 2024-08-28 10:42

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("analysis", "0004_rename_photo_analyst_analyst_image_and_more"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="analysisreport",
            name="url",
        ),
        migrations.AddField(
            model_name="analysisreport",
            name="file",
            field=models.FileField(
                default=django.utils.timezone.now, upload_to="reports/"
            ),
            preserve_default=False,
        ),
    ]
