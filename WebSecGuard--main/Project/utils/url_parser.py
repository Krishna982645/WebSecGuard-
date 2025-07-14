#!/usr/bin/env python3
"""
URL Parser Utility for WebSecGuard
Handles URL parsing, domain extraction, and keyword detection
"""

import re
import urllib.parse
from urllib.parse import urlparse, parse_qs

class URLParser:
    """URL parsing and analysis utility"""
    
    def __init__(self):
        # Common phishing keywords
        self.phishing_keywords = [
            'login', 'signin', 'sign-in', 'account', 'verify', 'update',
            'secure', 'security', 'bank', 'paypal', 'ebay', 'amazon',
            'facebook', 'google', 'microsoft', 'apple', 'netflix',
            'password', 'credential', 'personal', 'private', 'confirm',
            'validate', 'authenticate', 'authorize', 'check', 'review'
        ]
        
        # Suspicious TLDs
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free domains
            '.xyz', '.top', '.club', '.online', '.site', '.website'
        ]
        
        # IP address pattern
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
        # URL shortening services
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd',
            'v.gd', 'ow.ly', 'su.pr', 'twurl.nl', 'snipurl.com'
        ]
        
    def parse_url(self, url):
        """
        Parse a URL and extract components
        Returns: dict with parsed components
        """
        try:
            parsed = urlparse(url)
            
            return {
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'path': parsed.path,
                'query': parsed.query,
                'fragment': parsed.fragment,
                'domain': self.extract_domain(parsed.netloc),
                'subdomain': self.extract_subdomain(parsed.netloc),
                'tld': self.extract_tld(parsed.netloc),
                'query_params': parse_qs(parsed.query),
                'is_ip': self.is_ip_address(parsed.netloc),
                'is_shortened': self.is_shortened_url(parsed.netloc)
            }
        except Exception as e:
            return {
                'error': str(e),
                'original_url': url
            }
            
    def extract_domain(self, netloc):
        """Extract the main domain from netloc"""
        if not netloc:
            return ""
            
        # Remove port if present
        if ':' in netloc:
            netloc = netloc.split(':')[0]
            
        parts = netloc.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return netloc
        
    def extract_subdomain(self, netloc):
        """Extract subdomain from netloc"""
        if not netloc:
            return ""
            
        # Remove port if present
        if ':' in netloc:
            netloc = netloc.split(':')[0]
            
        parts = netloc.split('.')
        if len(parts) > 2:
            return '.'.join(parts[:-2])
        return ""
        
    def extract_tld(self, netloc):
        """Extract top-level domain from netloc"""
        if not netloc:
            return ""
            
        # Remove port if present
        if ':' in netloc:
            netloc = netloc.split(':')[0]
            
        parts = netloc.split('.')
        if len(parts) >= 1:
            return '.' + parts[-1]
        return ""
        
    def is_ip_address(self, netloc):
        """Check if netloc is an IP address"""
        if not netloc:
            return False
            
        # Remove port if present
        if ':' in netloc:
            netloc = netloc.split(':')[0]
            
        return bool(self.ip_pattern.match(netloc))
        
    def is_shortened_url(self, netloc):
        """Check if URL is from a shortening service"""
        if not netloc:
            return False
            
        # Remove port if present
        if ':' in netloc:
            netloc = netloc.split(':')[0]
            
        return netloc.lower() in self.url_shorteners
        
    def find_keywords(self, text, keyword_list=None):
        """
        Find keywords in text
        Args:
            text: Text to search in
            keyword_list: List of keywords to search for (defaults to phishing_keywords)
        Returns: List of found keywords
        """
        if keyword_list is None:
            keyword_list = self.phishing_keywords
            
        found_keywords = []
        text_lower = text.lower()
        
        for keyword in keyword_list:
            if keyword.lower() in text_lower:
                found_keywords.append(keyword)
                
        return found_keywords
        
    def analyze_url_structure(self, url):
        """
        Analyze URL structure for suspicious patterns
        Returns: dict with analysis results
        """
        parsed = self.parse_url(url)
        
        analysis = {
            'suspicious_patterns': [],
            'risk_factors': [],
            'overall_risk': 'low'
        }
        
        # Check for IP address
        if parsed.get('is_ip', False):
            analysis['suspicious_patterns'].append('uses_ip_address')
            analysis['risk_factors'].append('IP addresses are often used in phishing attacks')
            
        # Check for suspicious TLD
        tld = parsed.get('tld', '')
        if tld in self.suspicious_tlds:
            analysis['suspicious_patterns'].append('suspicious_tld')
            analysis['risk_factors'].append(f'Suspicious TLD: {tld}')
            
        # Check for keywords in domain
        domain = parsed.get('domain', '')
        domain_keywords = self.find_keywords(domain)
        if domain_keywords:
            analysis['suspicious_patterns'].append('suspicious_keywords_in_domain')
            analysis['risk_factors'].append(f'Suspicious keywords in domain: {", ".join(domain_keywords)}')
            
        # Check for keywords in path
        path = parsed.get('path', '')
        path_keywords = self.find_keywords(path)
        if path_keywords:
            analysis['suspicious_patterns'].append('suspicious_keywords_in_path')
            analysis['risk_factors'].append(f'Suspicious keywords in path: {", ".join(path_keywords)}')
            
        # Check for URL shortening
        if parsed.get('is_shortened', False):
            analysis['suspicious_patterns'].append('shortened_url')
            analysis['risk_factors'].append('URL shortening services can hide malicious destinations')
            
        # Check for HTTP instead of HTTPS
        if parsed.get('scheme') == 'http':
            analysis['suspicious_patterns'].append('http_protocol')
            analysis['risk_factors'].append('HTTP protocol is not secure')
            
        # Check for long subdomain
        subdomain = parsed.get('subdomain', '')
        if len(subdomain) > 30:
            analysis['suspicious_patterns'].append('long_subdomain')
            analysis['risk_factors'].append('Unusually long subdomain')
            
        # Calculate overall risk
        risk_score = len(analysis['suspicious_patterns'])
        if risk_score >= 3:
            analysis['overall_risk'] = 'high'
        elif risk_score >= 1:
            analysis['overall_risk'] = 'medium'
            
        return analysis
        
    def normalize_url(self, url):
        """
        Normalize URL for comparison
        Returns: normalized URL string
        """
        try:
            parsed = urlparse(url)
            
            # Convert to lowercase
            netloc = parsed.netloc.lower()
            
            # Remove www prefix
            if netloc.startswith('www.'):
                netloc = netloc[4:]
                
            # Remove trailing slash from path
            path = parsed.path.rstrip('/')
            if not path:
                path = '/'
                
            # Reconstruct URL
            normalized = f"{parsed.scheme}://{netloc}{path}"
            
            if parsed.query:
                normalized += f"?{parsed.query}"
            if parsed.fragment:
                normalized += f"#{parsed.fragment}"
                
            return normalized
        except Exception:
            return url.lower()
            
    def is_similar_domain(self, domain1, domain2, threshold=0.8):
        """
        Check if two domains are similar (potential homograph attack)
        Args:
            domain1: First domain
            domain2: Second domain
            threshold: Similarity threshold (0-1)
        Returns: bool
        """
        # Simple similarity check using edit distance
        def edit_distance(s1, s2):
            if len(s1) < len(s2):
                return edit_distance(s2, s1)
            
            if len(s2) == 0:
                return len(s1)
            
            previous_row = list(range(len(s2) + 1))
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            
            return previous_row[-1]
        
        distance = edit_distance(domain1.lower(), domain2.lower())
        max_length = max(len(domain1), len(domain2))
        similarity = 1 - (distance / max_length)
        
        return similarity >= threshold
        
    def extract_common_domains(self, urls):
        """
        Extract common legitimate domains from a list of URLs
        Useful for detecting homograph attacks
        """
        domains = {}
        
        for url in urls:
            parsed = self.parse_url(url)
            domain = parsed.get('domain', '')
            if domain:
                domains[domain] = domains.get(domain, 0) + 1
                
        # Return domains that appear multiple times
        return {domain: count for domain, count in domains.items() if count > 1}
        
    def validate_url(self, url):
        """
        Basic URL validation
        Returns: bool indicating if URL is valid
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False 