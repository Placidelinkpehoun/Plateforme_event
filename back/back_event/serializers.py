from rest_framework import serializers
from .models import *
from django.contrib import auth
from rest_framework_simplejwt.tokens import RefreshToken

class RegisterUtilisateurSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password', 'telephone']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            telephone=validated_data['telephone'],
            role='utilisateur'
        )
        return user

class RegisterOrganisateurSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)  # Ajout de validation
    ville = serializers.CharField(required=True)
    telephone = serializers.CharField(required=True)  # Explicitement requis

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password', 'telephone', 'ville']
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': True}
        }

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Un utilisateur avec cet email existe déjà")
        return value

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            telephone=validated_data['telephone'],
            ville=validated_data['ville'],
            role='organisateur',
            is_staff=False  # Ne donnez pas is_staff=True par défaut
        )
        return user
    
class OrganizerSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrganizerValidation
        fields = ['NPI', 'IFU', 'company_name', 'email_orga', 'tel_orga', 'description']
        extra_kwargs = {
            'user': {'read_only': True}
        }

    def validate_NPI(self, value):
        if len(value) != 14 or not value.isdigit():
            raise serializers.ValidationError("Le NPI doit contenir 14 chiffres")
        return value

    def validate_IFU(self, value):
        if len(value) != 14 or not value.isdigit():
            raise serializers.ValidationError("L'IFU doit contenir 14 chiffres")
        return value
    
class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(max_length=128, write_only=True)
    tokens = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        return obj.token()  # Appelle directement la méthode token() de l'utilisateur

    class Meta:
        model = User
        fields = ['email', 'password', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        if not email or not password:
            raise serializers.ValidationError("Email and password are required.")

        user = auth.authenticate(email=email, password=password)

        if not user:
            raise serializers.ValidationError("Invalid credentials.")

        return user  # Retourne l'objet utilisateur
    
class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            # Blacklist le token refresh
            RefreshToken(self.token).blacklist()
        except Exception as e:
            raise serializers.ValidationError("Token is invalid or expired.")