from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

class User(AbstractUser):
    """Custom User model with additional fields"""
    email = models.EmailField(unique=True)
    company = models.CharField(max_length=255, blank=True)
    is_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Rate limiting fields
    api_calls_today = models.IntegerField(default=0)
    last_api_call = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'auth_user'
    
    def __str__(self):
        return self.username

class UserActivity(models.Model):
    """Track user activities for audit logging"""
    ACTIVITY_TYPES = [
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('SUBMIT', 'Email Submission'),
        ('VIEW', 'View Result'),
        ('EXPORT', 'Export Report'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='activities')
    activity_type = models.CharField(max_length=20, choices=ACTIVITY_TYPES)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.JSONField(default=dict)
    
    class Meta:
        ordering = ['-timestamp']