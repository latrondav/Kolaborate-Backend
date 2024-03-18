from django.shortcuts import redirect, render
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth.models import User
from .models import *
from .serializers import *
from django.contrib.auth import authenticate, login
import random
import string
from django.contrib.sites.shortcuts import get_current_site
from KolaborateAPIProject import settings
from django.views.decorators.csrf import csrf_exempt
from django.utils.http import urlencode
import requests
from django.http import JsonResponse

# Create your views here.
def Landing(request):
    return render(request, 'landing.html')

@api_view(['POST'])
def RegisterIndividual(request):
    if request.method == 'POST':
        user_data = {
            "username": request.data.get("email"),
            "email": request.data.get("email"),
            "password": request.data.get("password"),
            "password2": request.data.get("password2"),
            "first_name": request.data.get("firstname"),
            "last_name": request.data.get("lastname"),
        }

        user_serializer = UserSerializer(data=user_data)
        
        if user_serializer.is_valid():
            try:
                email = user_serializer.validated_data['email'].lower()
                username = user_serializer.validated_data['username'].lower()
                firstname = user_serializer.validated_data['first_name']
                lastname = user_serializer.validated_data['last_name']
                password = user_serializer.validated_data['password']
                password2 = user_serializer.validated_data['password2']

                if User.objects.filter(email=email).exists():
                    return Response({"message": "Email Already Registered, Please Use A Different Email"}, status=status.HTTP_400_BAD_REQUEST)

                if User.objects.filter(username=username).exists():
                    return Response({"message": "Username Already Registered, Please Use A Different Username"}, status=status.HTTP_400_BAD_REQUEST)

                if password != password2:
                    return Response({"message": "Passwords Didn't Match"}, status=status.HTTP_400_BAD_REQUEST)

                # Generate a random 6-digit activation code
                activation_code = ''.join(random.choices('0123456789', k=6))

                user = User.objects.create_user(username, email, password)
                user.first_name = firstname.upper()
                user.last_name = lastname.upper()
                user.is_active = False
                user.save()

                # Create the profile for the user
                individual_profile_data = {
                    "user": user.id,
                    "contact": request.data.get("contact"),
                    # "date_of_birth": request.data.get("date_of_birth"),
                    "activation_code": activation_code,  # Save the activation code
                }
                individual_profile_serializer = RegisterIndividualProfileSerializer(data=individual_profile_data)
                if individual_profile_serializer.is_valid():
                    contact = individual_profile_serializer.validated_data['contact']
                    if IndividualProfile.objects.filter(contact=contact).exists():
                        return Response({"message": "Contact/Telephone Number Already Registered, Please Use A Different Contact/Telephone Number"}, status=status.HTTP_400_BAD_REQUEST)
                    
                    individual_profile_serializer.save()
                else:
                    # Rollback the user creation if profile creation fails
                    user.delete()
                    return Response({"message": f"Failed to create profile. {individual_profile_serializer.errors}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                # # You might want to send an activation email or SMS here
                # # Construct email messages
                # welcome_message = (
                #     f"Dear {firstname} {lastname},\n\n"
                #     f"Welcome to Kolaborate!\n\n"
                #     f"We're thrilled to have you join us on your financial journey. Thank you for choosing Kolaborate for your financial needs.\n\n"
                #     f"To get started, please activate your account by following these simple steps:\n\n"
                #     f"1. Input your email address ({email}) and the activation code ({activation_code}) provided below.\n"
                #     f"2. Submit the information to complete the activation process.\n\n"
                #     f"Rest assured, your security is our top priority, and we're committed to safeguarding your information every step of the way.\n\n"
                #     f"If you encounter any issues or have questions, our dedicated support team is here to assist you. Feel free to reach out at any time.\n\n"
                #     f"Thank you once again for trusting Kolaborate. We look forward to serving you and helping you achieve your financial goals.\n\n"
                #     f"Warm regards,\n\n"
                #     "Kolaborate System Demon."
                # )

                # # Create EmailMessage instances
                # welcome_email = EmailMessage(
                #     subject="Activate Your Kolaborate Account Now",
                #     body=welcome_message,
                #     from_email=settings.EMAIL_HOST_USER,
                #     to=[email]
                # )
                # welcome_email.send(fail_silently=False)

                return Response({"message": f"Kolaborate Account Created. Activation code sent to {email}."}, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({"message": f"Failed To Create Kolaborate Account. {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({"message": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)
    return Response({"message": "Method not allowed"}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@api_view(['POST'])
def ActivateAccount(request):
    if request.method == 'POST':
        email = request.data.get("email")
        activation_code = request.data.get("activation_code")

        if not email or not activation_code:
            return Response({"message": "Email and activation code are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"message": "User does not exist."}, status=status.HTTP_404_NOT_FOUND)

        try:
            profile = IndividualProfile.objects.get(user=user, activation_code=activation_code)
            if profile:
                # Activate the user
                user.is_active = True
                user.save()

                return Response({"message": "Account activated successfully. Proceed To Login"}, status=status.HTTP_200_OK)
        except IndividualProfile.DoesNotExist:
            return Response({"message": "Invalid activation code."}, status=status.HTTP_400_BAD_REQUEST)
    return Response({"message": "Method not allowed"}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@api_view(['POST'])
def Login(request):
    if request.method == 'POST':
        try:
            # Check if user exists with provided email
            email = request.data.get('username')
            user = User.objects.get(email=email)

            if user:
                # Check if the user account is active
                if not user.is_active:
                    # Account is not activated
                    return Response({"message": "Account is not activated. Please check your email or contact support for assistance."}, status=status.HTTP_403_FORBIDDEN)

                # Proceed with authentication using credentials
                username = user.username
                password = request.data.get('password')
                user = authenticate(username=username, password=password)

                if user:
                    # Generate JWT token
                    access_token = AccessToken.for_user(user)

                    # Retrieve the role associated with the user
                    # role = user.individualprofile.individual_role.role  # Accessing the name attribute of the related Role object

                    combined_data = {
                        'user_data': {
                            'id': user.pk,
                            'email': user.email,
                            # 'role': role
                        },
                        'token': str(access_token)
                    }
                    return Response({"message": "Logged In Successfully", "user_data": combined_data}, status=status.HTTP_202_ACCEPTED)
                else:
                    # Authentication failed
                    return Response({"message": "Login failed. Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            # User does not exist
            return Response({"message": "Login failed. User does not exist."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            # Other unexpected errors
            return Response({"message": f"Login failed: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
    return Response({"message": "Method not allowed"}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

# @csrf_exempt
# def GoogleSignIn(request):
#     # Redirect user to Google Sign-In page
#     protocol = "https" if request.is_secure() else "http"
#     domain = request.get_host()
#     google_auth_url = 'https://accounts.google.com/o/oauth2/v2/auth'
#     redirect_uri = f'{protocol}://{domain}/googleauthcallback/'
#     client_id = settings.GOOGLE_CLIENT_ID
#     state = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
#     scope = 'openid email profile'
#     params = {
#         'response_type': 'code',
#         'client_id': client_id,
#         'redirect_uri': redirect_uri,
#         'scope': scope,
#         'state': state
#     }
#     auth_url = f'{google_auth_url}?{urlencode(params)}'
#     return redirect(auth_url)

# def GoogleAuthCallback(request):
#     # Handle Google Sign-In callback
#     code = request.GET.get('code')
#     if code:
#         current_site = get_current_site(request)
#         domain = current_site.domain
#         protocol = "https" if request.is_secure() else "http"
#         token_endpoint = 'https://oauth2.googleapis.com/token'
#         client_id = settings.GOOGLE_CLIENT_ID
#         client_secret = settings.GOOGLE_SECRET_KEY
#         redirect_uri = f'{protocol}://{domain}/googleauthcallback/'
#         data = {
#             'code': code,
#             'client_id': client_id,
#             'client_secret': client_secret,
#             'redirect_uri': redirect_uri,
#             'grant_type': 'authorization_code'
#         }
#         response = requests.post(token_endpoint, data=data)
#         if response.status_code == 200:
#             access_token = response.json().get('id_token')
            
#             # Pass the access token within a dictionary to the serializer
#             serializer = GoogleSignInSerializer(data={'access_token': access_token})
#             if serializer.is_valid(raise_exception=True):
#                 data = serializer.validated_data.get('access_token')
#                 return JsonResponse(data, status=status.HTTP_200_OK)
#         else:
#             return JsonResponse({'error': 'Failed to obtain access token'}, status=status.HTTP_400_BAD_REQUEST)
#     else:
#         return JsonResponse({'error': 'Authorization code missing'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def GoogleSignIn(request):
    if request.method == 'POST':
        serializer = GoogleSignInSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            data = serializer.validated_data.get('access_token')
            return JsonResponse(data, status=status.HTTP_200_OK)
    return Response({"message": "Method not allowed"}, status=status.HTTP_405_METHOD_NOT_ALLOWED)



