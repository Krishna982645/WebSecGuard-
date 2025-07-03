#!/usr/bin/env python3
"""
Secure Browser Component for WebSecGuard
Handles web browsing with integrated threat detection
"""

from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage, QWebEngineProfile
from PyQt5.QtWebEngineCore import QWebEngineUrlRequestInterceptor, QWebEngineUrlRequestInfo
from PyQt5.QtCore import QUrl, pyqtSignal, QObject
from PyQt5.QtWidgets import QMessageBox, QApplication
import re

class SecurityInterceptor(QWebEngineUrlRequestInterceptor):
    """Intercepts web requests for security analysis"""
    
    def __init__(self, threat_scanner, logger):
        super().__init__()
        self.threat_scanner = threat_scanner
        self.logger = logger
        
    def interceptRequest(self, info):
        """Intercept and analyze web requests"""
        url = info.requestUrl().toString()
        
        # Skip if auto-scan is disabled
        if not self.threat_scanner.auto_scan:
            return
            
        # Check if URL is in blacklist
        if self.logger.is_blacklisted(url):
            info.block(True)
            self.logger.log_security_event(url, "BLOCKED", "URL in blacklist", "high")
            return
            
        # Check if URL is in whitelist
        if self.logger.is_whitelisted(url):
            self.logger.log_security_event(url, "ALLOWED", "URL in whitelist", "low")
            return
            
        # Perform threat analysis
        threat_result = self.threat_scanner.analyze_url(url)
        
        if threat_result['threat_level'] == 'high':
            # Block the request
            info.block(True)
            self.logger.log_security_event(url, "BLOCKED", threat_result['reason'], "high")
            
            # Show warning to user
            QMessageBox.warning(None, "Security Warning", 
                f"Access to {url} has been blocked due to security concerns:\n\n"
                f"{threat_result['reason']}\n\n"
                "This URL has been added to your blacklist.")
                
        elif threat_result['threat_level'] == 'medium':
            # Allow but warn user
            self.logger.log_security_event(url, "WARNED", threat_result['reason'], "medium")
            
            reply = QMessageBox.question(None, "Security Warning",
                f"Warning: {url} may be suspicious:\n\n"
                f"{threat_result['reason']}\n\n"
                "Do you want to continue?",
                QMessageBox.Yes | QMessageBox.No)
                
            if reply == QMessageBox.No:
                info.block(True)
                self.logger.log_security_event(url, "BLOCKED", "User chose to block", "medium")
                
        else:
            # Safe URL
            self.logger.log_security_event(url, "ALLOWED", "URL appears safe", "low")

class SecureWebPage(QWebEnginePage):
    """Custom web page with security features"""
    
    def __init__(self, profile, threat_scanner, logger):
        super().__init__(profile)
        self.threat_scanner = threat_scanner
        self.logger = logger
        
    def javaScriptConsoleMessage(self, level, message, lineNumber, sourceID):
        """Monitor JavaScript console messages for suspicious activity"""
        suspicious_keywords = ['eval', 'document.write', 'innerHTML', 'script', 'alert']
        
        for keyword in suspicious_keywords:
            if keyword.lower() in message.lower():
                self.logger.log_security_event(
                    sourceID, 
                    "WARNING", 
                    f"Suspicious JavaScript detected: {message}", 
                    "medium"
                )
                break

class SecureBrowser(QWebEngineView):
    """Main secure browser component"""
    
    url_changed = pyqtSignal(str)
    security_alert = pyqtSignal(str, str)  # message, level
    
    def __init__(self, threat_scanner, logger):
        super().__init__()
        
        self.threat_scanner = threat_scanner
        self.logger = logger
        
        # Create secure profile
        self.profile = QWebEngineProfile("WebSecGuard", self)
        self.profile.setHttpCacheType(QWebEngineProfile.MemoryHttpCache)
        
        # Set up security interceptor
        self.interceptor = SecurityInterceptor(threat_scanner, logger)
        self.profile.setUrlRequestInterceptor(self.interceptor)
        
        # Create secure page
        self.page = SecureWebPage(self.profile, threat_scanner, logger)
        self.setPage(self.page)
        
        # Connect signals
        self.urlChanged.connect(self._on_url_changed)
        self.loadFinished.connect(self._on_load_finished)
        self.loadStarted.connect(self._on_load_started)
        
        # Security settings
        self.page.settings().setAttribute(self.page.settings().JavascriptEnabled, True)
        self.page.settings().setAttribute(self.page.settings().PluginsEnabled, False)
        self.page.settings().setAttribute(self.page.settings().AutoLoadImages, True)
        self.page.settings().setAttribute(self.page.settings().JavascriptCanOpenWindows, False)
        self.page.settings().setAttribute(self.page.settings().JavascriptCanAccessClipboard, False)
        
    def _on_url_changed(self, url):
        """Handle URL changes"""
        url_str = url.toString()
        self.url_changed.emit(url_str)
        
        # Log navigation
        self.logger.log_security_event(url_str, "NAVIGATION", "User navigated to URL", "info")
        
    def _on_load_started(self):
        """Handle page load start"""
        current_url = self.url().toString()
        self.logger.log_security_event(current_url, "LOADING", "Page load started", "info")
        
    def _on_load_finished(self, success):
        """Handle page load completion"""
        current_url = self.url().toString()
        
        if success:
            self.logger.log_security_event(current_url, "LOADED", "Page loaded successfully", "info")
            
            # Perform post-load security analysis
            self._analyze_loaded_page()
        else:
            self.logger.log_security_event(current_url, "ERROR", "Page failed to load", "warning")
            
    def _analyze_loaded_page(self):
        """Analyze the loaded page for security issues"""
        current_url = self.url().toString()
        
        # Check for HTTP vs HTTPS
        if current_url.startswith('http://') and not current_url.startswith('https://'):
            self.security_alert.emit(
                "Warning: This page is using HTTP instead of HTTPS. "
                "Your data may not be encrypted during transmission.",
                "warning"
            )
            
        # Check for suspicious elements
        self.page.runJavaScript("""
        (function() {
            var suspicious = [];
            
            // Check for forms without HTTPS
            var forms = document.querySelectorAll('form');
            forms.forEach(function(form) {
                if (form.action && form.action.startsWith('http://')) {
                    suspicious.push('Form submission over HTTP: ' + form.action);
                }
            });
            
            // Check for external scripts
            var scripts = document.querySelectorAll('script[src]');
            scripts.forEach(function(script) {
                if (script.src && !script.src.startsWith(window.location.origin)) {
                    suspicious.push('External script: ' + script.src);
                }
            });
            
            // Check for iframes
            var iframes = document.querySelectorAll('iframe');
            if (iframes.length > 0) {
                suspicious.push('Page contains ' + iframes.length + ' iframe(s)');
            }
            
            return suspicious;
        })();
        """, self._on_javascript_analysis)
        
    def _on_javascript_analysis(self, result):
        """Handle JavaScript analysis results"""
        if result and len(result) > 0:
            for issue in result:
                self.logger.log_security_event(
                    self.url().toString(),
                    "ANALYSIS",
                    f"Page analysis issue: {issue}",
                    "medium"
                )
                self.security_alert.emit(f"Page analysis: {issue}", "warning")
                
    def navigate_to_url(self, url):
        """Navigate to a specific URL with security checks"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        # Perform pre-navigation security check
        threat_result = self.threat_scanner.analyze_url(url)
        
        if threat_result['threat_level'] == 'high':
            self.security_alert.emit(
                f"Navigation blocked: {threat_result['reason']}",
                "danger"
            )
            return False
        elif threat_result['threat_level'] == 'medium':
            self.security_alert.emit(
                f"Navigation warning: {threat_result['reason']}",
                "warning"
            )
            
        self.load(QUrl(url))
        return True
        
    def go_back(self):
        """Navigate back with security logging"""
        if self.history().canGoBack():
            self.back()
            self.logger.log_security_event(
                self.url().toString(),
                "NAVIGATION",
                "User navigated back",
                "info"
            )
            
    def go_forward(self):
        """Navigate forward with security logging"""
        if self.history().canGoForward():
            self.forward()
            self.logger.log_security_event(
                self.url().toString(),
                "NAVIGATION",
                "User navigated forward",
                "info"
            )
            
    def reload(self):
        """Reload current page with security logging"""
        current_url = self.url().toString()
        self.logger.log_security_event(current_url, "RELOAD", "Page reloaded", "info")
        super().reload()
        
    def get_current_url(self):
        """Get the current URL"""
        return self.url().toString()
        
    def get_page_title(self):
        """Get the current page title"""
        return self.title()
        
    def is_loading(self):
        """Check if page is currently loading"""
        return self.isLoading() 