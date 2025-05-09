from django.urls import path
from . import views

from rest_framework_simplejwt.views import (
    TokenRefreshView  
)

app_name = 'back_event'
urlpatterns = [
    path('register/utilisateur/', views.RegisterUtilisateurView.as_view(), name='register-utilisateur'),
    path('register/organisateur/', views.RegisterOrganisateurView.as_view(), name='register-organisateur'),
    path('register/organisateur/validation/', views.OrganizerView.as_view(), name='register-organisateur-validation'),
    path('admin/validate/<int:user_id>/', views.AdminOrganizerApprovalView.as_view()),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('api/token/refresh', TokenRefreshView.as_view(), name='token_refresh'),  # Corrigé ici
    path('api/user/me/', views.UserMeView.as_view()),
    path('profile/', views.UserProfileView.as_view(), name='user-profile'),
]