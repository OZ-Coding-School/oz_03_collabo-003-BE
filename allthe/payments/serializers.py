from rest_framework import serializers

from .models import Payment


class PaymentSerializer(serializers.Serializer):
    imp_uid = serializers.CharField()
    merchant_uid = serializers.CharField()
    paid_amount = serializers.FloatField()
    apply_num = serializers.CharField()
