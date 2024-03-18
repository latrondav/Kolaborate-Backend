from django.urls import path
from . import views

urlpatterns = [
    path('var/task/register/individual/', views.RegisterIndividual),
    path('var/task/activateaccount/', views.ActivateAccount),
    path('var/task/login/', views.Login),
    path('var/task/googlesignin/', views.GoogleSignIn),
    # path('googleauthcallback/', views.GoogleAuthCallback),
]