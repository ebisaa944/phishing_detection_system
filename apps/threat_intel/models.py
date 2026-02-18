from django.db import models
from apps.detection_engine.models import AnalysisResult

class ThreatIntelCheck(models.Model):
    """Threat intelligence lookup results"""
    analysis = models.OneToOneField(AnalysisResult, on_delete=models.CASCADE, related_name='threat_intel')
    
    # URL intelligence
    urls_checked = models.JSONField(default=list)
    malicious_urls = models.JSONField(default=list)
    suspicious_urls = models.JSONField(default=list)
    
    # Domain intelligence
    domain_reputation = models.JSONField(default=dict)
    domain_age_days = models.IntegerField(null=True, blank=True)
    domain_registrar = models.CharField(max_length=255, null=True, blank=True)
    domain_sinkhole = models.BooleanField(default=False)
    
    # IP intelligence
    ip_reputation = models.JSONField(default=dict)
    ip_geolocation = models.JSONField(default=dict)
    ip_asn = models.CharField(max_length=100, null=True, blank=True)
    
    # External service results
    virustotal_results = models.JSONField(default=dict)
    shodan_results = models.JSONField(default=dict)
    abuseipdb_results = models.JSONField(default=dict)
    
    # Overall threat score (0-100)
    threat_score = models.FloatField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)

class ThreatFeed(models.Model):
    """Threat intelligence feeds configuration"""
    FEED_TYPES = [
        ('URL', 'URL Feed'),
        ('DOMAIN', 'Domain Feed'),
        ('IP', 'IP Feed'),
        ('HASH', 'File Hash Feed'),
    ]
    
    name = models.CharField(max_length=255)
    feed_type = models.CharField(max_length=20, choices=FEED_TYPES)
    url = models.URLField()
    api_key = models.CharField(max_length=255, blank=True)
    update_interval = models.IntegerField(help_text="Update interval in hours")
    last_updated = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    entries = models.JSONField(default=list)  # Cached feed entries
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)