from rest_framework import serializers
from django.contrib.auth.models import User
from .models import *
from .utils import *
from KolaborateAPIProject import settings
from rest_framework.exceptions import AuthenticationFailed

class UserSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password2', 'first_name', 'last_name']

    def validate(self, data):
        # Check if the passwords match
        if data['password'] != data['password2']:
            raise serializers.ValidationError("Passwords must match.")
        return data

    def create(self, validated_data):
        # Remove 'password2' from the validated data before creating the user
        validated_data.pop('password2', None)
        return super(UserSerializer, self).create(validated_data)

class RegisterIndividualProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = IndividualProfile
        fields = ['user', 'contact', 'activation_code']

class UserDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name']

class IndividualProfileDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = IndividualProfile
        fields = ['contact']

class GoogleSignInSerializer(serializers.Serializer):
    access_token=serializers.CharField(min_length=6)

    def validate_access_token(self, access_token):
        google_user_data=Google.validate(access_token)
        try:
            userid=google_user_data["sub"]
        except:
            raise serializers.ValidationError("This Is An Invalid token Or Has Expired.")

        if google_user_data['aud'] != settings.GOOGLE_CLIENT_ID:
            # Authentication failed
            Google_Valid_Failed = {
                "message": "Could Not Verify Google Client User."
            }
            return Google_Valid_Failed
        email=google_user_data['email']
        first_name=google_user_data['given_name']
        last_name=google_user_data['family_name']
        provider="Google"
        picture=google_user_data['picture']
        password=settings.GOOGLE_SOCIAL_USER_PASSWORD

        return register_social_user(first_name, last_name, email, provider, picture, password)