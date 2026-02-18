from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta

User = get_user_model()

class DashboardStats(models.Model):
    """Cached dashboard statistics"""
    date = models.DateField(unique=True)
    
    # Overall stats
    total_analyses = models.IntegerField(default=0)
    total_users = models.IntegerField(default=0)
    phishing_detected = models.IntegerField(default=0)
    suspicious_detected = models.IntegerField(default=0)
    legitimate_detected = models.IntegerField(default=0)
    
    # Time-based stats
    analyses_last_24h = models.IntegerField(default=0)
    phishing_last_24h = models.IntegerField(default=0)
    
    # Performance stats
    avg_response_time = models.FloatField(default=0)  # in seconds
    avg_confidence = models.FloatField(default=0)
    
    # Model performance
    model_accuracy = models.FloatField(default=0)
    model_precision = models.FloatField(default=0)
    model_recall = models.FloatField(default=0)
    model_f1_score = models.FloatField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-date']

class Alert(models.Model):
    """System alerts for administrators"""
    ALERT_TYPES = [
        ('INFO', 'Information'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('CRITICAL', 'Critical'),
    ]
    
    title = models.CharField(max_length=255)
    message = models.TextField()
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPES)
    is_resolved = models.BooleanField(default=False)
    resolved_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']