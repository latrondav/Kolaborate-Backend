from google.auth.transport import requests
from google.oauth2 import id_token
from django.contrib.auth.models import User
from .models import *
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse

class Google():
    @staticmethod
    def validate(access_token):
        try:
            id_info=id_token.verify_oauth2_token(access_token,requests.Request())
            if "accounts.google.com" in id_info['iss']:
                return id_info
        except Exception as e:
            return "Token is invalid or has expired"

def register_social_user(first_name, last_name, email, provider, picture, password):
    user = User.objects.filter(email=email)
    if user.exists():
        if provider == user[0].individualprofile.auth_provider:
            existinguser = authenticate(username=email, password=password)
            existinguser_token = AccessToken.for_user(existinguser)
            existinguser_combined_data = {
                'user_data': {
                    'id': existinguser.pk,
                    'email': existinguser.email,
                    # 'role': role
                },
                'token': str(existinguser_token)
            }
            return existinguser_combined_data
        else:
            # Authentication failed
            Google_Social_Auth_Failed = {
                "message": f"Please Continue Your Login With {user[0].individualprofile.auth_provider} And Password."
            }
            return Google_Social_Auth_Failed
    else:
        user_data = {
            "username": email,
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "password": password,
        }
        newsocialuser = User.objects.create_user(**user_data)
        newsocialuser.first_name = first_name.upper()
        newsocialuser.last_name = last_name.upper()
        newsocialuser.is_active = True
        newsocialuser.save()

        profile = IndividualProfile(
            user=newsocialuser,
            auth_provider=provider
        )
        profile.save()

        autheduser = authenticate(username=email, password=password)

        if autheduser:
            # Generate JWT token
            autheduser_token = AccessToken.for_user(autheduser)

            # Retrieve the role associated with the user
            # role = user.individualprofile.individual_role.role  # Accessing the name attribute of the related Role object

            autheduser_combined_data = {
                'user_data': {
                    'id': autheduser.pk,
                    'email': autheduser.email,
                    # 'role': role
                },
                'token': str(autheduser_token)
            }
            return autheduser_combined_data
        else:
            # Authentication failed
            Google_Social_Auth_Failed = {
                "message": "Login failed. Invalid credentials."
            }
            return Google_Social_Auth_Failed
