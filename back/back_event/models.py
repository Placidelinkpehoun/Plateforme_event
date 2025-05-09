"use client"
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from rest_framework_simplejwt.tokens import RefreshToken

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_organizer(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        
        email = self.normalize_email(email)
        user = self.model(
            email=email,
            role='organisateur',
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)

    def get_by_natural_key(self, email):
        return self.get(email=email)  # Recherche l'utilisateur par email


class User(AbstractBaseUser):
    id = models.AutoField(primary_key=True)

    ROLE_CHOICES = [
        ('organisateur', 'Organisateur'),
        ('utilisateur', 'Utilisateur'),
    ]
    is_organizer_validated = models.BooleanField(default=False)
    validation_data = models.JSONField(null=True, blank=True)

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='utilisateur')

    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=100)

    ville = models.CharField(max_length=100, blank=True, null=True)  # Ville de l'utilisateur
    telephone = models.CharField(max_length=15)  # Numéro de téléphone de l'utilisateur

    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)  # Indique si l'utilisateur est actif
    is_staff = models.BooleanField(default=True)  # Indique si l'utilisateur a accès à l'admin

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'telephone']

    objects = UserManager()

    def __str__(self):
        return f"{self.email} ({self.role})"
    
    def token(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
    
class OrganizerValidation(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    NPI = models.CharField(max_length=14)
    IFU = models.CharField(max_length=14)
    company_name = models.CharField(max_length=255)
    email_orga = models.EmailField(unique=True)
    tel_orga = models.CharField(max_length=15)
    description = models.CharField(max_length=255, blank=True, null=True)
    is_approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

