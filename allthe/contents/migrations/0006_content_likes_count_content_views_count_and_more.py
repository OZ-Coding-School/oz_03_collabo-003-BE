# Generated by Django 5.1 on 2024-09-03 06:21

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("contents", "0005_remove_content_images_contentimage_content_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="content",
            name="likes_count",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="content",
            name="views_count",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name="contentimage",
            name="content",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="images",
                to="contents.content",
            ),
        ),
    ]
