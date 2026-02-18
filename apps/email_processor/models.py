from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class EmailSubmission(models.Model):
    """Raw email submission"""
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='submissions')
    subject = models.CharField(max_length=255)
    sender = models.EmailField()
    recipient = models.EmailField(null=True, blank=True)
    body = models.TextField()
    raw_email = models.TextField(null=True, blank=True)  # For full email
    attachments = models.JSONField(default=list)  # Store attachment metadata
    submitted_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    processing_time = models.FloatField(null=True, blank=True)
    
    class Meta:
        ordering = ['-submitted_at']

class ParsedEmail(models.Model):
    """Structured email data after parsing"""
    submission = models.OneToOneField(EmailSubmission, on_delete=models.CASCADE, related_name='parsed')
    
    # Email structure
    message_id = models.CharField(max_length=255)
    in_reply_to = models.CharField(max_length=255, null=True, blank=True)
    content_type = models.CharField(max_length=100)
    
    # Parsed components
    clean_body = models.TextField()
    urls = models.JSONField(default=list)
    urls_extracted = models.JSONField(default=list)  # URLs with metadata
    headers = models.JSONField(default=dict)
    has_html = models.BooleanField(default=False)
    
    # Security indicators
    has_forms = models.BooleanField(default=False)
    has_scripts = models.BooleanField(default=False)
    has_iframes = models.BooleanField(default=False)
    has_attachments = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)