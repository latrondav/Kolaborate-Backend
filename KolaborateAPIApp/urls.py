from django.urls import path
from . import views

urlpatterns = [
    path('register/individual/', views.RegisterIndividual),
    path('activateaccount/', views.ActivateAccount),
    path('login/', views.Login),
    path('googlesignin/', views.GoogleSignIn),
    # path('googleauthcallback/', views.GoogleAuthCallback),
]