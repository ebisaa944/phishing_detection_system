import re
import urllib.parse
from typing import Dict, List, Any
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
import nltk
from nltk.corpus import stopwords
import tldextract
import textstat

# Download NLTK data
nltk.download('stopwords')
nltk.download('punkt')

class FeatureExtractor:
    """Extract features from emails for ML processing"""
    
    def __init__(self):
        self.stop_words = set(stopwords.words('english'))
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 3)
        )
        
        # Common phishing indicators
        self.urgency_words = [
            'urgent', 'immediately', 'alert', 'critical', 'important',
            'suspended', 'limited', 'expire', 'verify', 'confirm',
            'account', 'security', 'update', 'restore', 'action required'
        ]
        
        self.financial_words = [
            'bank', 'paypal', 'credit card', 'visa', 'mastercard',
            'western union', 'money gram', 'transfer', 'wire',
            'refund', 'invoice', 'payment', 'transaction'
        ]
        
        self.personal_info_words = [
            'password', 'ssn', 'social security', 'date of birth',
            'mother\'s maiden name', 'credit score', 'pin',
            'username', 'login', 'sign in', 'verify your identity'
        ]
        
        self.suspicious_tlds = [
            '.xyz', '.top', '.work', '.date', '.men', '.loan',
            '.download', '.review', '.stream', '.gdn', '.racing',
            '.win', '.bid', '.trade', '.webcam', '.science'
        ]
    
    def extract_all_features(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract all features from email data"""
        features = {}
        
        # Extract text features
        features.update(self._extract_text_features(email_data.get('body', '')))
        
        # Extract URL features
        features.update(self._extract_url_features(email_data.get('urls', [])))
        
        # Extract email metadata features
        features.update(self._extract_metadata_features(email_data))
        
        # Extract attachment features
        features.update(self._extract_attachment_features(email_data.get('attachments', [])))
        
        # Extract behavioral features
        features.update(self._extract_behavioral_features(email_data.get('body', '')))
        
        # Generate TF-IDF features
        features['tfidf_vector'] = self._get_tfidf_features(email_data.get('body', ''))
        
        return features
    
    def _extract_text_features(self, text: str) -> Dict[str, float]:
        """Extract features from text content"""
        if not text:
            return {
                'word_count': 0,
                'char_count': 0,
                'sentence_count': 0,
                'avg_word_length': 0,
                'unique_word_ratio': 0,
                'uppercase_ratio': 0,
                'punctuation_count': 0,
                'readability_score': 0
            }
        
        words = nltk.word_tokenize(text.lower())
        sentences = nltk.sent_tokenize(text)
        unique_words = set(words)
        
        word_count = len(words)
        char_count = len(text)
        
        features = {
            'word_count': word_count,
            'char_count': char_count,
            'sentence_count': len(sentences),
            'avg_word_length': char_count / word_count if word_count > 0 else 0,
            'unique_word_ratio': len(unique_words) / word_count if word_count > 0 else 0,
            'uppercase_ratio': sum(1 for c in text if c.isupper()) / char_count if char_count > 0 else 0,
            'punctuation_count': sum(1 for c in text if c in '.,!?;:'),
            'readability_score': textstat.flesch_reading_ease(text)
        }
        
        return features
    
    def _extract_url_features(self, urls: List[str]) -> Dict[str, Any]:
        """Extract features from URLs"""
        features = {
            'url_count': len(urls),
            'suspicious_url_count': 0,
            'ip_url_count': 0,
            'shortened_url_count': 0,
            'suspicious_tld_count': 0,
            'url_entropy': [],
            'has_https': [],
        }
        
        url_shorteners = [
            'bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'short.link', 'tiny.cc'
        ]
        
        for url in urls:
            # Check for IP address in URL
            if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
                features['ip_url_count'] += 1
                features['suspicious_url_count'] += 1
            
            # Check for URL shorteners
            if any(shortener in url for shortener in url_shorteners):
                features['shortened_url_count'] += 1
                features['suspicious_url_count'] += 1
            
            # Check TLD
            extracted = tldextract.extract(url)
            if extracted.suffix:
                if any(tld in extracted.suffix for tld in self.suspicious_tlds):
                    features['suspicious_tld_count'] += 1
                    features['suspicious_url_count'] += 1
            
            # Check HTTPS
            features['has_https'].append(url.startswith('https'))
            
            # Calculate URL entropy (randomness)
            url_entropy = self._calculate_entropy(url)
            features['url_entropy'].append(url_entropy)
            if url_entropy > 4.5:  # High entropy indicates random characters
                features['suspicious_url_count'] += 1
        
        # Aggregate features
        features['avg_url_entropy'] = np.mean(features['url_entropy']) if features['url_entropy'] else 0
        features['https_ratio'] = sum(features['has_https']) / len(features['has_https']) if features['has_https'] else 0
        
        # Clean up temporary fields
        del features['url_entropy']
        del features['has_https']
        
        return features
    
    def _extract_metadata_features(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from email metadata"""
        features = {
            'has_reply_to': False,
            'reply_to_mismatch': False,
            'has_spf_fail': False,
            'has_dkim_fail': False,
            'has_dmarc_fail': False,
            'has_html': False,
            'has_forms': False,
            'has_scripts': False,
            'has_iframes': False,
        }
        
        headers = email_data.get('headers', {})
        
        # Check Reply-To mismatch
        if headers.get('Reply-To'):
            features['has_reply_to'] = True
            if headers.get('Reply-To') != headers.get('From'):
                features['reply_to_mismatch'] = True
                features['has_reply_to'] = True
        
        # Authentication results
        auth_results = headers.get('Authentication-Results', '')
        features['has_spf_fail'] = 'spf=fail' in auth_results.lower()
        features['has_dkim_fail'] = 'dkim=fail' in auth_results.lower()
        
        # HTML features
        features['has_html'] = email_data.get('has_html', False)
        features['has_forms'] = email_data.get('has_forms', False)
        features['has_scripts'] = email_data.get('has_scripts', False)
        features['has_iframes'] = email_data.get('has_iframes', False)
        
        return features
    
    def _extract_attachment_features(self, attachments: List[Dict]) -> Dict[str, Any]:
        """Extract features from email attachments"""
        suspicious_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.vbs', '.ps1',
            '.js', '.jar', '.docm', '.xlsm', '.pptm'
        ]
        
        features = {
            'attachment_count': len(attachments),
            'suspicious_attachment_count': 0,
            'executable_attachment_count': 0,
            'max_attachment_size': 0,
            'has_encrypted_attachment': False
        }
        
        for attachment in attachments:
            name = attachment.get('name', '')
            size = attachment.get('size', 0)
            
            # Check extension
            ext = '.' + name.split('.')[-1].lower() if '.' in name else ''
            if ext in suspicious_extensions:
                features['suspicious_attachment_count'] += 1
                if ext in ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.ps1']:
                    features['executable_attachment_count'] += 1
            
            # Check size
            features['max_attachment_size'] = max(features['max_attachment_size'], size)
            
            # Check if encrypted (simplified - check for .enc, .encrypted, .pgp)
            if any(x in name.lower() for x in ['.enc', '.encrypted', '.pgp', '.gpg']):
                features['has_encrypted_attachment'] = True
        
        return features
    
    def _extract_behavioral_features(self, text: str) -> Dict[str, Any]:
        """Extract behavioral indicators from text"""
        text_lower = text.lower()
        
        features = {
            'urgency_words_count': 0,
            'financial_words_count': 0,
            'personal_info_words_count': 0,
            'has_urgency': False,
            'has_financial': False,
            'has_personal_info_request': False
        }
        
        # Count urgency words
        for word in self.urgency_words:
            features['urgency_words_count'] += text_lower.count(word)
        features['has_urgency'] = features['urgency_words_count'] > 0
        
        # Count financial words
        for word in self.financial_words:
            features['financial_words_count'] += text_lower.count(word)
        features['has_financial'] = features['financial_words_count'] > 0
        
        # Count personal info request words
        for word in self.personal_info_words:
            features['personal_info_words_count'] += text_lower.count(word)
        features['has_personal_info_request'] = features['personal_info_words_count'] > 0
        
        return features
    
    def _get_tfidf_features(self, text: str) -> List[float]:
        """Generate TF-IDF features for text"""
        if not text:
            return [0] * 1000
        
        # Fit and transform (in production, you'd use a pre-fitted vectorizer)
        tfidf_matrix = self.tfidf_vectorizer.fit_transform([text])
        return tfidf_matrix.toarray()[0].tolist()
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not s:
            return 0
        
        entropy = 0
        for i in range(256):
            char = chr(i)
            freq = s.count(char)
            if freq > 0:
                freq = float(freq) / len(s)
                entropy -= freq * (freq and np.log2(freq) or 0)
        
        return entropy
    
    def prepare_ml_input(self, features: Dict[str, Any]) -> np.ndarray:
        """Prepare features for ML model input"""
        # Convert features to numpy array
        feature_vector = []
        
        # Numerical features
        numerical_features = [
            'word_count', 'char_count', 'sentence_count', 'avg_word_length',
            'unique_word_ratio', 'uppercase_ratio', 'punctuation_count',
            'url_count', 'suspicious_url_count', 'ip_url_count',
            'shortened_url_count', 'suspicious_tld_count', 'avg_url_entropy',
            'https_ratio', 'urgency_words_count', 'financial_words_count',
            'personal_info_words_count', 'attachment_count',
            'suspicious_attachment_count', 'executable_attachment_count'
        ]
        
        for feature in numerical_features:
            feature_vector.append(float(features.get(feature, 0)))
        
        # Boolean features (convert to 0/1)
        boolean_features = [
            'has_reply_to', 'reply_to_mismatch', 'has_spf_fail',
            'has_dkim_fail', 'has_html', 'has_forms', 'has_scripts',
            'has_iframes', 'has_urgency', 'has_financial',
            'has_personal_info_request', 'has_encrypted_attachment'
        ]
        
        for feature in boolean_features:
            feature_vector.append(1 if features.get(feature, False) else 0)
        
        return np.array(feature_vector).reshape(1, -1)