# Generated by Django 5.1 on 2024-09-04 05:05

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("contents", "0007_remove_content_likes_count_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="content",
            name="thumbnail",
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="contentimage",
            name="file",
            field=models.TextField(blank=True, null=True),
        ),
    ]
