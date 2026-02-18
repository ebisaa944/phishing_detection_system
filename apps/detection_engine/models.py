from django.db import models
from django.contrib.auth import get_user_model
from apps.email_processor.models import EmailSubmission

User = get_user_model()

class ExtractedFeatures(models.Model):
    """Features extracted from email for ML processing"""
    submission = models.OneToOneField(EmailSubmission, on_delete=models.CASCADE, related_name='features')
    
    # Text features
    word_count = models.IntegerField()
    char_count = models.IntegerField()
    sentence_count = models.IntegerField()
    avg_word_length = models.FloatField()
    unique_word_ratio = models.FloatField()
    uppercase_ratio = models.FloatField()
    punctuation_count = models.IntegerField()
    
    # URL features
    url_count = models.IntegerField(default=0)
    suspicious_url_count = models.IntegerField(default=0)
    ip_url_count = models.IntegerField(default=0)
    shortened_url_count = models.IntegerField(default=0)
    suspicious_tld_count = models.IntegerField(default=0)
    
    # Email features
    has_reply_to = models.BooleanField(default=False)
    reply_to_mismatch = models.BooleanField(default=False)
    has_spf_fail = models.BooleanField(default=False)
    has_dkim_fail = models.BooleanField(default=False)
    
    # Attachment features
    attachment_count = models.IntegerField(default=0)
    suspicious_attachment_count = models.IntegerField(default=0)
    executable_attachment_count = models.IntegerField(default=0)
    
    # Behavioral features
    urgency_words_count = models.IntegerField(default=0)
    financial_words_count = models.IntegerField(default=0)
    personal_info_words_count = models.IntegerField(default=0)
    
    # TF-IDF vectors (stored as JSON)
    tfidf_features = models.JSONField(default=dict)
    
    created_at = models.DateTimeField(auto_now_add=True)

class AnalysisResult(models.Model):
    """Final analysis result"""
    CLASSIFICATION_CHOICES = [
        ('LEGITIMATE', 'Legitimate'),
        ('SUSPICIOUS', 'Suspicious'),
        ('PHISHING', 'Phishing'),
    ]
    
    submission = models.OneToOneField(EmailSubmission, on_delete=models.CASCADE, related_name='result')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='analysis_results')
    
    # Scores
    rule_score = models.FloatField()
    ml_score = models.FloatField()
    threat_intel_score = models.FloatField(null=True, blank=True)
    final_score = models.FloatField()
    
    # Classification
    classification = models.CharField(max_length=20, choices=CLASSIFICATION_CHOICES)
    confidence = models.FloatField()
    
    # Model details
    ml_model_used = models.CharField(max_length=50)
    ml_model_version = models.CharField(max_length=20)
    
    # Explanations
    explanation = models.JSONField(default=list)  # List of reasons
    triggered_rules = models.JSONField(default=list)
    
    # Flags
    is_whitelisted = models.BooleanField(default=False)
    is_blacklisted = models.BooleanField(default=False)
    requires_review = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']

class Rule(models.Model):
    """Detection rules for rule engine"""
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField()
    condition = models.TextField()  # Python expression
    score = models.FloatField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    category = models.CharField(max_length=50)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name

class RuleHit(models.Model):
    """Record of rules triggered"""
    analysis = models.ForeignKey(AnalysisResult, on_delete=models.CASCADE, related_name='rule_hits')
    rule = models.ForeignKey(Rule, on_delete=models.CASCADE)
    matched_value = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)