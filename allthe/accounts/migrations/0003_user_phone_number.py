# Generated by Django 5.1 on 2024-08-22 19:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0002_remove_user_provider_user_business_number_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="phone_number",
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]