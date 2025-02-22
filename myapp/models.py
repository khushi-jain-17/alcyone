from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.base_user import BaseUserManager


class CustomUserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifiers
    for authentication instead of usernames.
    """
    def create_user(self, email, password, **extra_fields):
        """
        Create and save a user with the given email and password.
        """
        if not email:
            raise ValueError("The Email must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault("role", "admin")
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    username = models.CharField(max_length=200, unique=True)
    email = models.EmailField(unique=True)

    # class Role(models.TextChoices): 
    #     ADMIN = "admin"
    #     MANAGER = "manager"
    #     SUPPORT_STAFF = "support_staff"
    #     CLIENT = "client"
    #     VIEWER = "viewer"
    
    role = models.CharField(max_length=30, choices=[('client', 'Client'), ('admin', 'Admin'), ('manager','Manager'),('viewer','Viewer'),('support_staff','Support_staff')] )

    objects = CustomUserManager()
    def __str__(self):
        return self.email



class Ticket(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    status = models.CharField(max_length=200)
    created_by = models.CharField(max_length=100, null=True)
    # assigned_to = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, null=True, related_name='tickets', on_delete=models.CASCADE)
    deleted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    # updated_by = models.CharField(max_length=100, null=True)

    def __str__(self):
        return self.title
    

class Log(models.Model):
    ACTION_CHOICES = [
        ('CREATE', 'Created'),
        ('UPDATE', 'Updated'),
        ('DELETE', 'Deleted'),
        ('VIEW', 'View'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    description = models.TextField()
    ticket = models.ForeignKey(Ticket, null=True, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.user.username} {self.action} at {self.timestamp}"















class Client(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    