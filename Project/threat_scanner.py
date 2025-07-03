#!/usr/bin/env python3
"""
Threat Scanner Component for WebSecGuard
Analyzes URLs and web content for security threats
"""

import re
import urllib.parse
import ipaddress
from datetime import datetime

class ThreatScanner:
    """Main threat scanning engine"""
    
    def __init__(self, logger):
        self.logger = logger
        self.auto_scan = True
        self.strict_mode = False
        
        # Suspicious patterns
        self.suspicious_keywords = [
            'login', 'signin', 'sign-in', 'account', 'verify', 'update',
            'secure', 'security', 'bank', 'paypal', 'ebay', 'amazon',
            'facebook', 'google', 'microsoft', 'apple', 'netflix',
            'password', 'credential', 'personal', 'private'
        ]
        
        # Known malicious domains (example)
        self.malicious_domains = [
            'malware.example.com',
            'phishing.example.com',
            'scam.example.com'
        ]
        
        # Suspicious TLDs
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free domains often used for phishing
            '.xyz', '.top', '.club', '.online'
        ]
        
        # IP address patterns
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
        # Homograph attack patterns
        self.homograph_patterns = [
            (r'[0-9]', 'o'),  # 0 looks like o
            (r'[1]', 'l'),    # 1 looks like l
            (r'[5]', 's'),    # 5 looks like s
            (r'[8]', 'b'),    # 8 looks like b
        ]
        
    def analyze_url(self, url):
        """
        Analyze a URL for security threats
        Returns: dict with threat_level, reason, and details
        """
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path.lower()
            query = parsed_url.query.lower()
            
            threat_score = 0
            reasons = []
            details = {}
            
            # Check 1: IP address instead of domain
            if self._is_ip_address(domain):
                threat_score += 30
                reasons.append("Uses IP address instead of domain name")
                details['ip_address'] = domain
                
            # Check 2: Suspicious TLD
            if self._has_suspicious_tld(domain):
                threat_score += 20
                reasons.append("Uses suspicious top-level domain")
                details['suspicious_tld'] = self._get_tld(domain)
                
            # Check 3: HTTP instead of HTTPS
            if parsed_url.scheme == 'http':
                threat_score += 15
                reasons.append("Uses HTTP instead of HTTPS")
                details['protocol'] = 'http'
                
            # Check 4: Suspicious keywords in domain
            keyword_matches = self._find_suspicious_keywords(domain)
            if keyword_matches:
                threat_score += len(keyword_matches) * 10
                reasons.append(f"Contains suspicious keywords: {', '.join(keyword_matches)}")
                details['suspicious_keywords'] = keyword_matches
                
            # Check 5: Suspicious keywords in path
            path_keywords = self._find_suspicious_keywords(path)
            if path_keywords:
                threat_score += len(path_keywords) * 5
                reasons.append(f"Path contains suspicious keywords: {', '.join(path_keywords)}")
                details['path_keywords'] = path_keywords
                
            # Check 6: Homograph attack detection
            homograph_result = self._detect_homograph_attack(domain)
            if homograph_result:
                threat_score += 25
                reasons.append(f"Possible homograph attack: {homograph_result}")
                details['homograph'] = homograph_result
                
            # Check 7: Known malicious domain
            if domain in self.malicious_domains:
                threat_score += 50
                reasons.append("Domain is in known malicious list")
                details['malicious_domain'] = True
                
            # Check 8: Subdomain analysis
            subdomain_analysis = self._analyze_subdomains(domain)
            if subdomain_analysis['suspicious']:
                threat_score += subdomain_analysis['score']
                reasons.append(subdomain_analysis['reason'])
                details['subdomain_analysis'] = subdomain_analysis
                
            # Check 9: Query parameter analysis
            query_analysis = self._analyze_query_parameters(query)
            if query_analysis['suspicious']:
                threat_score += query_analysis['score']
                reasons.append(query_analysis['reason'])
                details['query_analysis'] = query_analysis
                
            # Check 10: URL length and complexity
            if len(url) > 200:
                threat_score += 10
                reasons.append("Unusually long URL")
                details['url_length'] = len(url)
                
            # Determine threat level
            threat_level = self._calculate_threat_level(threat_score)
            
            return {
                'threat_level': threat_level,
                'threat_score': threat_score,
                'reason': '; '.join(reasons) if reasons else "URL appears safe",
                'details': details,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'threat_level': 'unknown',
                'threat_score': 0,
                'reason': f"Error analyzing URL: {str(e)}",
                'details': {},
                'timestamp': datetime.now().isoformat()
            }
            
    def _is_ip_address(self, domain):
        """Check if domain is an IP address"""
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False
            
    def _has_suspicious_tld(self, domain):
        """Check if domain has suspicious TLD"""
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                return True
        return False
        
    def _get_tld(self, domain):
        """Get the TLD of a domain"""
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.' + parts[-1]
        return ''
        
    def _find_suspicious_keywords(self, text):
        """Find suspicious keywords in text"""
        found_keywords = []
        for keyword in self.suspicious_keywords:
            if keyword in text.lower():
                found_keywords.append(keyword)
        return found_keywords
        
    def _detect_homograph_attack(self, domain):
        """Detect potential homograph attacks"""
        # Common legitimate domains to check against
        legitimate_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'paypal.com',
            'ebay.com', 'microsoft.com', 'apple.com', 'netflix.com',
            'twitter.com', 'instagram.com', 'linkedin.com', 'github.com'
        ]
        
        for legit_domain in legitimate_domains:
            if self._similar_domain(domain, legit_domain):
                return f"Similar to {legit_domain}"
        return None
        
    def _similar_domain(self, domain1, domain2):
        """Check if two domains are similar (potential homograph attack)"""
        # Remove TLD for comparison
        domain1_base = domain1.split('.')[0]
        domain2_base = domain2.split('.')[0]
        
        # Simple similarity check (can be enhanced with more sophisticated algorithms)
        if len(domain1_base) == len(domain2_base):
            differences = sum(1 for a, b in zip(domain1_base, domain2_base) if a != b)
            if differences <= 2:  # Allow 2 character differences
                return True
        return False
        
    def _analyze_subdomains(self, domain):
        """Analyze subdomains for suspicious patterns"""
        parts = domain.split('.')
        
        if len(parts) <= 2:
            return {'suspicious': False, 'score': 0, 'reason': ''}
            
        subdomain = parts[0]
        score = 0
        reasons = []
        
        # Check for suspicious subdomain patterns
        if subdomain.startswith('www'):
            return {'suspicious': False, 'score': 0, 'reason': ''}
            
        # Check for random-looking subdomains
        if len(subdomain) > 20:
            score += 10
            reasons.append("Very long subdomain")
            
        # Check for suspicious characters
        if re.search(r'[0-9]{3,}', subdomain):
            score += 15
            reasons.append("Subdomain contains many numbers")
            
        # Check for suspicious keywords in subdomain
        subdomain_keywords = self._find_suspicious_keywords(subdomain)
        if subdomain_keywords:
            score += len(subdomain_keywords) * 10
            reasons.append(f"Suspicious keywords in subdomain: {', '.join(subdomain_keywords)}")
            
        return {
            'suspicious': score > 0,
            'score': score,
            'reason': '; '.join(reasons) if reasons else ''
        }
        
    def _analyze_query_parameters(self, query):
        """Analyze query parameters for suspicious content"""
        if not query:
            return {'suspicious': False, 'score': 0, 'reason': ''}
            
        score = 0
        reasons = []
        
        # Check for suspicious parameter names
        suspicious_params = ['password', 'passwd', 'pwd', 'user', 'username', 'email', 'credit', 'card']
        for param in suspicious_params:
            if param in query:
                score += 10
                reasons.append(f"Suspicious parameter: {param}")
                
        # Check for encoded content
        if '%' in query:
            score += 5
            reasons.append("Contains URL-encoded content")
            
        # Check for JavaScript in query
        if 'javascript:' in query or 'data:' in query:
            score += 20
            reasons.append("Contains JavaScript or data URI")
            
        return {
            'suspicious': score > 0,
            'score': score,
            'reason': '; '.join(reasons) if reasons else ''
        }
        
    def _calculate_threat_level(self, score):
        """Calculate threat level based on score"""
        if self.strict_mode:
            # More strict thresholds
            if score >= 40:
                return 'high'
            elif score >= 20:
                return 'medium'
            else:
                return 'low'
        else:
            # Standard thresholds
            if score >= 50:
                return 'high'
            elif score >= 25:
                return 'medium'
            else:
                return 'low'
                
    def analyze_content(self, html_content):
        """
        Analyze HTML content for security threats
        Returns: dict with threat_level, reason, and details
        """
        threat_score = 0
        reasons = []
        details = {}
        
        # Check for suspicious scripts
        script_patterns = [
            r'<script[^>]*src=["\']([^"\']*)["\'][^>]*>',
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'eval\(',
            r'document\.write\(',
            r'innerHTML\s*='
        ]
        
        for pattern in script_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE | re.DOTALL)
            if matches:
                threat_score += len(matches) * 5
                reasons.append(f"Found {len(matches)} suspicious script patterns")
                details['script_patterns'] = matches
                
        # Check for iframes
        iframe_matches = re.findall(r'<iframe[^>]*>', html_content, re.IGNORECASE)
        if iframe_matches:
            threat_score += len(iframe_matches) * 3
            reasons.append(f"Found {len(iframe_matches)} iframe(s)")
            details['iframes'] = iframe_matches
            
        # Check for forms
        form_matches = re.findall(r'<form[^>]*>', html_content, re.IGNORECASE)
        if form_matches:
            threat_score += len(form_matches) * 2
            reasons.append(f"Found {len(form_matches)} form(s)")
            details['forms'] = form_matches
            
        # Check for external resources
        external_patterns = [
            r'src=["\'](https?://[^"\']*)["\']',
            r'href=["\'](https?://[^"\']*)["\']'
        ]
        
        for pattern in external_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                threat_score += len(matches) * 1
                reasons.append(f"Found {len(matches)} external resource(s)")
                details['external_resources'] = matches
                
        # Determine threat level
        threat_level = self._calculate_threat_level(threat_score)
        
        return {
            'threat_level': threat_level,
            'threat_score': threat_score,
            'reason': '; '.join(reasons) if reasons else "Content appears safe",
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        
    def add_malicious_domain(self, domain):
        """Add a domain to the malicious domains list"""
        if domain not in self.malicious_domains:
            self.malicious_domains.append(domain)
            
    def remove_malicious_domain(self, domain):
        """Remove a domain from the malicious domains list"""
        if domain in self.malicious_domains:
            self.malicious_domains.remove(domain)
            
    def get_malicious_domains(self):
        """Get list of malicious domains"""
        return self.malicious_domains.copy()
        
    def update_suspicious_keywords(self, keywords):
        """Update the list of suspicious keywords"""
        self.suspicious_keywords.extend(keywords)
        
    def get_suspicious_keywords(self):
        """Get list of suspicious keywords"""
        return self.suspicious_keywords.copy() 