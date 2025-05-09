from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.response import Response
from .serializers import *
from .models import *
from rest_framework.decorators import permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib import auth
from datetime import timedelta

class RegisterUtilisateurView(generics.CreateAPIView):
    serializer_class = RegisterUtilisateurSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        print("Données reçues :", request.data)  # Log des données reçues
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if not serializer.is_valid():
            print("Erreurs de validation :", serializer.errors)  # Log des erreurs
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        user = serializer.save()
        return Response({
            'user': serializer.data,
            'tokens': user.token()
        }, status=status.HTTP_201_CREATED)

class RegisterOrganisateurView(generics.CreateAPIView):
    '''serializer_class = RegisterOrganisateurSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        print("Données reçues :", request.data)  # Log des données reçues
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if not serializer.is_valid():
            print("Erreurs de validation :", serializer.errors)  # Log des erreurs
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        user = serializer.save(is_organizer_validated=False)
        
        tokens = user.token()
        
        # Création d'un token temporaire spécifique à la validation
        from rest_framework_simplejwt.tokens import AccessToken
        validation_token = AccessToken.for_user(user)
        validation_token.set_exp(lifetime=timedelta(hours=24))  # Valable 24h
        
        redirect_url = (
            f"/orga-form?user_id={user.id}"
            f"&token={str(validation_token)}"
            f"&email={user.email}"
        )
        
        return Response({
            "status": "additional_info_required",
            "redirect_url": redirect_url,
            "tokens": tokens
        }, status=status.HTTP_202_ACCEPTED)'''
    serializer_class = RegisterOrganisateurSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save(is_organizer_validated=False)
        
        tokens = user.token()
        
        return Response({
            "status": "additional_info_required",
            "redirect_url": "/orga-form",  # URL propre sans paramètres
            "tokens": tokens
        }, status=status.HTTP_202_ACCEPTED)
    
class OrganizerView(APIView):
    serializer_class = OrganizerSerializer
    permission_classes = [IsAuthenticated]  # Protection par JWT standard

    def post(self, request):
        # L'utilisateur est automatiquement vérifié via le token JWT
        user = request.user
        
        # Vérification que l'utilisateur est bien un organisateur
        if user.role != 'organisateur':
            return Response(
                {"error": "Seuls les organisateurs peuvent soumettre ce formulaire"},
                status=status.HTTP_403_FORBIDDEN
            )

        # Vérification qu'une demande n'existe pas déjà
        if OrganizerValidation.objects.filter(user=user).exists():
            return Response(
                {"error": "Une demande de validation existe déjà pour cet utilisateur"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validation et traitement des données
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Création de la validation
        OrganizerValidation.objects.create(
            user=user,
            **serializer.validated_data
        )

        # Mise à jour du statut de l'utilisateur
        user.is_organizer_validated = True  # Ou False si besoin de validation admin
        user.save()

        return Response({
            "status": "success",
            "message": "Demande de validation enregistrée avec succès",
            "data": serializer.data
        }, status=status.HTTP_201_CREATED)
      
class UserMeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': user.role
        })
    
class AdminOrganizerApprovalView(generics.UpdateAPIView):
    queryset = OrganizerValidation.objects.all()
    serializer_class = OrganizerSerializer
    permission_classes = [IsAdminUser]
    lookup_field = 'user_id'

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        is_approved = request.data.get('is_approved', False)
        
        instance.is_approved = is_approved
        instance.save()
        
        # Mettre à jour le user
        user = instance.user
        user.is_organizer_validated = is_approved
        user.save()
        
        # Envoyer un email de notification
        # send_approval_email(user.email, is_approved)
        
        return Response({"status": "approved" if is_approved else "rejected"})

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data  # L'utilisateur est retourné par le sérialiseur

        tokens = user.token()  # Appelle la méthode token() de l'utilisateur

        if user.role == 'organisateur' and not user.is_organizer_validated:
            return Response({
                "error": "validation_required",
                "redirect_url": "/orga-form/",
                "tokens": tokens
            }, status=status.HTTP_403_FORBIDDEN)

        response_data = {
            "email": user.email,
            "tokens": user.token(),  # Appelle la méthode token() de l'utilisateur
        }
        return Response(response_data, status=status.HTTP_200_OK)
        
class LogoutView(APIView):
    authentication_classes = []
    serializer_class = LogoutSerializer
    @permission_classes([AllowAny])
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"details": "User logged out successfully"}, status=status.HTTP_200_OK)
    
class TokenLoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        token = request.data.get('token')

        user = User.objects.filter(username=username, token=token).first()
        if user is not None:
            user.login_token = None
            user.save()
            response = Response({"detail": "Logged in successfully"}, status=status.HTTP_200_OK)
            response.set_cookie('refreshtoken', user.token.refreshtoken, secure=True, samesite=None)
            return response
        else:     
            return Response({"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        data = {
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': user.role,
            'telephone': user.telephone,
            'ville': user.ville,
            'is_organizer_validated': user.is_organizer_validated if hasattr(user, 'is_organizer_validated') else None
        }
        return Response(data)