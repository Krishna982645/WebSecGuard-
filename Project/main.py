#!/usr/bin/env python3
"""
WebSecGuard - A Browser-Integrated Cyber Threat Monitor
Main Application Entry Point
"""

import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QTabWidget, QPushButton, QLineEdit, QLabel, QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox, QSplitter, QFrame, QGroupBox, QCheckBox, QComboBox, QSpinBox, QFileDialog
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QUrl
from PyQt5.QtGui import QIcon, QFont, QPalette, QColor
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage, QWebEngineProfile
from PyQt5.QtWebEngineCore import QWebEngineUrlRequestInterceptor

from browser import SecureBrowser
from threat_scanner import ThreatScanner
from logger import SecurityLogger
from utils.url_parser import URLParser
from utils.password_checker import PasswordLeakChecker

class WebSecGuard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WebSecGuard - Cyber Threat Monitor")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize components
        self.logger = SecurityLogger()
        self.threat_scanner = ThreatScanner(self.logger)
        self.url_parser = URLParser()
        self.password_checker = PasswordLeakChecker()
        
        # Setup UI
        self.setup_ui()
        self.setup_styles()
        
        # Initialize browser BEFORE setting up connections
        self.browser = SecureBrowser(self.threat_scanner, self.logger)
        self.browser_layout.addWidget(self.browser)
        
        # Setup connections AFTER browser is created
        self.setup_connections()
        
        # Load initial page
        self.browser.load(QUrl("https://www.google.com"))
        
        # Security score
        self.security_score = 100
        self.update_security_score()
        
    def setup_ui(self):
        """Setup the main user interface"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QHBoxLayout(central_widget)
        
        # Left panel for controls and info
        left_panel = QWidget()
        left_panel.setMaximumWidth(300)
        left_layout = QVBoxLayout(left_panel)
        
        # Security score display
        self.score_label = QLabel("Security Score: 100")
        self.score_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #2ecc71;")
        left_layout.addWidget(self.score_label)
        
        # Browser controls
        browser_controls = QGroupBox("Browser Controls")
        browser_layout = QVBoxLayout(browser_controls)
        
        # URL bar
        url_layout = QHBoxLayout()
        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("Enter URL...")
        url_layout.addWidget(self.url_bar)
        
        # Navigation buttons
        nav_layout = QHBoxLayout()
        self.back_btn = QPushButton("←")
        self.forward_btn = QPushButton("→")
        self.reload_btn = QPushButton("↻")
        self.home_btn = QPushButton("🏠")
        
        nav_layout.addWidget(self.back_btn)
        nav_layout.addWidget(self.forward_btn)
        nav_layout.addWidget(self.reload_btn)
        nav_layout.addWidget(self.home_btn)
        
        browser_layout.addLayout(url_layout)
        browser_layout.addLayout(nav_layout)
        left_layout.addWidget(browser_controls)
        
        # Threat alerts panel
        self.alerts_group = QGroupBox("Security Alerts")
        self.alerts_layout = QVBoxLayout(self.alerts_group)
        self.alerts_text = QTextEdit()
        self.alerts_text.setMaximumHeight(150)
        self.alerts_text.setReadOnly(True)
        self.alerts_layout.addWidget(self.alerts_text)
        left_layout.addWidget(self.alerts_group)
        
        # Settings panel
        settings_group = QGroupBox("Settings")
        settings_layout = QVBoxLayout(settings_group)
        
        self.auto_scan_cb = QCheckBox("Auto-scan URLs")
        self.auto_scan_cb.setChecked(True)
        self.strict_mode_cb = QCheckBox("Strict detection mode")
        self.dark_mode_cb = QCheckBox("Dark mode")
        
        settings_layout.addWidget(self.auto_scan_cb)
        settings_layout.addWidget(self.strict_mode_cb)
        settings_layout.addWidget(self.dark_mode_cb)
        left_layout.addWidget(settings_group)
        
        # Password leak checker
        pwd_group = QGroupBox("Password Leak Checker")
        pwd_layout = QVBoxLayout(pwd_group)
        
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter email to check...")
        self.check_pwd_btn = QPushButton("Check Password Leaks")
        
        pwd_layout.addWidget(self.email_input)
        pwd_layout.addWidget(self.check_pwd_btn)
        left_layout.addWidget(pwd_group)
        
        left_layout.addStretch()
        
        # Right panel for browser and tabs
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # Tab widget for different views
        self.tab_widget = QTabWidget()
        
        # Browser tab
        browser_tab = QWidget()
        self.browser_layout = QVBoxLayout(browser_tab)
        self.tab_widget.addTab(browser_tab, "🌐 Browser")
        
        # Logs tab
        logs_tab = QWidget()
        logs_layout = QVBoxLayout(logs_tab)
        
        logs_controls = QHBoxLayout()
        self.export_logs_btn = QPushButton("Export Logs")
        self.clear_logs_btn = QPushButton("Clear Logs")
        logs_controls.addWidget(self.export_logs_btn)
        logs_controls.addWidget(self.clear_logs_btn)
        logs_controls.addStretch()
        
        self.logs_table = QTableWidget()
        self.logs_table.setColumnCount(5)
        self.logs_table.setHorizontalHeaderLabels(["Timestamp", "URL", "Threat Level", "Action", "Details"])
        header = self.logs_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        
        logs_layout.addLayout(logs_controls)
        logs_layout.addWidget(self.logs_table)
        self.tab_widget.addTab(logs_tab, "📋 Logs")
        
        # Blacklist/Whitelist tab
        lists_tab = QWidget()
        lists_layout = QVBoxLayout(lists_tab)
        
        # Blacklist section
        blacklist_group = QGroupBox("Blacklist")
        blacklist_layout = QVBoxLayout(blacklist_group)
        
        blacklist_input_layout = QHBoxLayout()
        self.blacklist_input = QLineEdit()
        self.blacklist_input.setPlaceholderText("Enter URL to blacklist...")
        self.add_blacklist_btn = QPushButton("Add")
        blacklist_input_layout.addWidget(self.blacklist_input)
        blacklist_input_layout.addWidget(self.add_blacklist_btn)
        
        self.blacklist_table = QTableWidget()
        self.blacklist_table.setColumnCount(2)
        self.blacklist_table.setHorizontalHeaderLabels(["URL", "Date Added"])
        
        blacklist_layout.addLayout(blacklist_input_layout)
        blacklist_layout.addWidget(self.blacklist_table)
        lists_layout.addWidget(blacklist_group)
        
        # Whitelist section
        whitelist_group = QGroupBox("Whitelist")
        whitelist_layout = QVBoxLayout(whitelist_group)
        
        whitelist_input_layout = QHBoxLayout()
        self.whitelist_input = QLineEdit()
        self.whitelist_input.setPlaceholderText("Enter URL to whitelist...")
        self.add_whitelist_btn = QPushButton("Add")
        whitelist_input_layout.addWidget(self.whitelist_input)
        whitelist_input_layout.addWidget(self.add_whitelist_btn)
        
        self.whitelist_table = QTableWidget()
        self.whitelist_table.setColumnCount(2)
        self.whitelist_table.setHorizontalHeaderLabels(["URL", "Date Added"])
        
        whitelist_layout.addLayout(whitelist_input_layout)
        whitelist_layout.addWidget(self.whitelist_table)
        lists_layout.addWidget(whitelist_group)
        
        self.tab_widget.addTab(lists_tab, "⚫⚪ Lists")
        
        # Educational tab
        edu_tab = QWidget()
        edu_layout = QVBoxLayout(edu_tab)
        
        self.edu_text = QTextEdit()
        self.edu_text.setReadOnly(True)
        self.edu_text.setHtml("""
        <h2>🔒 Cybersecurity Education</h2>
        <h3>Common Threats:</h3>
        <ul>
        <li><b>Phishing:</b> Fake websites that mimic legitimate ones</li>
        <li><b>Malware:</b> Harmful software that can damage your system</li>
        <li><b>Homograph Attacks:</b> URLs that look similar but are different</li>
        <li><b>HTTP vs HTTPS:</b> Always prefer secure HTTPS connections</li>
        </ul>
        
        <h3>Safety Tips:</h3>
        <ul>
        <li>Check the URL carefully before entering credentials</li>
        <li>Look for the padlock icon in the address bar</li>
        <li>Never click on suspicious links in emails</li>
        <li>Use strong, unique passwords for each account</li>
        <li>Enable two-factor authentication when possible</li>
        </ul>
        
        <h3>Red Flags:</h3>
        <ul>
        <li>URLs with IP addresses instead of domain names</li>
        <li>Misspelled domain names (g00gle.com instead of google.com)</li>
        <li>HTTP instead of HTTPS for login pages</li>
        <li>Urgent requests for personal information</li>
        <li>Too-good-to-be-true offers</li>
        </ul>
        """)
        
        edu_layout.addWidget(self.edu_text)
        self.tab_widget.addTab(edu_tab, "📚 Education")
        
        right_layout.addWidget(self.tab_widget)
        
        # Add panels to main layout
        main_layout.addWidget(left_panel)
        main_layout.addWidget(right_panel, 1)
        
        # Load initial data
        self.load_logs()
        self.load_lists()
        
    def setup_styles(self):
        """Setup application styling"""
        self.setStyleSheet("""
        QMainWindow {
            background-color: #f0f0f0;
        }
        QGroupBox {
            font-weight: bold;
            border: 2px solid #cccccc;
            border-radius: 5px;
            margin-top: 1ex;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }
        QPushButton {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #2980b9;
        }
        QPushButton:pressed {
            background-color: #21618c;
        }
        QLineEdit {
            padding: 8px;
            border: 2px solid #bdc3c7;
            border-radius: 4px;
            background-color: white;
        }
        QLineEdit:focus {
            border-color: #3498db;
        }
        QTextEdit {
            border: 2px solid #bdc3c7;
            border-radius: 4px;
            background-color: white;
        }
        QTableWidget {
            border: 2px solid #bdc3c7;
            border-radius: 4px;
            background-color: white;
            gridline-color: #ecf0f1;
        }
        QTableWidget::item {
            padding: 5px;
        }
        QHeaderView::section {
            background-color: #34495e;
            color: white;
            padding: 8px;
            border: none;
            font-weight: bold;
        }
        """)
        
    def setup_connections(self):
        """Setup signal connections"""
        # Browser controls
        self.url_bar.returnPressed.connect(self.navigate_to_url)
        self.back_btn.clicked.connect(self.browser.back)
        self.forward_btn.clicked.connect(self.browser.forward)
        self.reload_btn.clicked.connect(self.browser.reload)
        self.home_btn.clicked.connect(self.go_home)
        
        # Settings
        self.dark_mode_cb.toggled.connect(self.toggle_dark_mode)
        self.auto_scan_cb.toggled.connect(self.toggle_auto_scan)
        self.strict_mode_cb.toggled.connect(self.toggle_strict_mode)
        
        # Password checker
        self.check_pwd_btn.clicked.connect(self.check_password_leaks)
        
        # Lists management
        self.add_blacklist_btn.clicked.connect(self.add_to_blacklist)
        self.add_whitelist_btn.clicked.connect(self.add_to_whitelist)
        
        # Logs management
        self.export_logs_btn.clicked.connect(self.export_logs)
        self.clear_logs_btn.clicked.connect(self.clear_logs)
        
    def navigate_to_url(self):
        """Navigate to the URL entered in the URL bar"""
        url = self.url_bar.text()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        self.browser.load(QUrl(url))
        
    def go_home(self):
        """Navigate to home page"""
        self.browser.load(QUrl("https://www.google.com"))
        
    def toggle_dark_mode(self, enabled):
        """Toggle dark mode"""
        if enabled:
            self.setStyleSheet(self.styleSheet() + """
            QMainWindow, QWidget {
                background-color: #2c3e50;
                color: #ecf0f1;
            }
            QGroupBox {
                border-color: #34495e;
            }
            QLineEdit, QTextEdit {
                background-color: #34495e;
                color: #ecf0f1;
                border-color: #7f8c8d;
            }
            QTableWidget {
                background-color: #34495e;
                color: #ecf0f1;
                gridline-color: #7f8c8d;
            }
            """)
        else:
            self.setup_styles()
            
    def toggle_auto_scan(self, enabled):
        """Toggle automatic URL scanning"""
        self.threat_scanner.auto_scan = enabled
        
    def toggle_strict_mode(self, enabled):
        """Toggle strict detection mode"""
        self.threat_scanner.strict_mode = enabled
        
    def check_password_leaks(self):
        """Check for password leaks using the email"""
        email = self.email_input.text().strip()
        if not email:
            QMessageBox.warning(self, "Warning", "Please enter an email address.")
            return
            
        try:
            result = self.password_checker.check_email(email)
            if result:
                QMessageBox.information(self, "Password Leak Check", 
                    f"Email {email} has been found in {result} data breaches.\n\n"
                    "Recommendations:\n"
                    "• Change your passwords immediately\n"
                    "• Use unique passwords for each account\n"
                    "• Enable two-factor authentication\n"
                    "• Consider using a password manager")
            else:
                QMessageBox.information(self, "Password Leak Check", 
                    f"Good news! Email {email} was not found in any known data breaches.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error checking password leaks: {str(e)}")
            
    def add_to_blacklist(self):
        """Add URL to blacklist"""
        url = self.blacklist_input.text().strip()
        if url:
            self.logger.add_to_blacklist(url)
            self.blacklist_input.clear()
            self.load_lists()
            QMessageBox.information(self, "Success", f"Added {url} to blacklist.")
        else:
            QMessageBox.warning(self, "Warning", "Please enter a URL.")
            
    def add_to_whitelist(self):
        """Add URL to whitelist"""
        url = self.whitelist_input.text().strip()
        if url:
            self.logger.add_to_whitelist(url)
            self.whitelist_input.clear()
            self.load_lists()
            QMessageBox.information(self, "Success", f"Added {url} to whitelist.")
        else:
            QMessageBox.warning(self, "Warning", "Please enter a URL.")
            
    def load_logs(self):
        """Load and display security logs"""
        logs = self.logger.get_logs()
        self.logs_table.setRowCount(len(logs))
        
        for i, log in enumerate(logs):
            self.logs_table.setItem(i, 0, QTableWidgetItem(log['timestamp']))
            self.logs_table.setItem(i, 1, QTableWidgetItem(log['url']))
            self.logs_table.setItem(i, 2, QTableWidgetItem(log['threat_level']))
            self.logs_table.setItem(i, 3, QTableWidgetItem(log['action']))
            self.logs_table.setItem(i, 4, QTableWidgetItem(log['details']))
            
    def load_lists(self):
        """Load blacklist and whitelist"""
        # Load blacklist
        blacklist = self.logger.get_blacklist()
        self.blacklist_table.setRowCount(len(blacklist))
        for i, item in enumerate(blacklist):
            self.blacklist_table.setItem(i, 0, QTableWidgetItem(item['url']))
            self.blacklist_table.setItem(i, 1, QTableWidgetItem(item['date_added']))
            
        # Load whitelist
        whitelist = self.logger.get_whitelist()
        self.whitelist_table.setRowCount(len(whitelist))
        for i, item in enumerate(whitelist):
            self.whitelist_table.setItem(i, 0, QTableWidgetItem(item['url']))
            self.whitelist_table.setItem(i, 1, QTableWidgetItem(item['date_added']))
            
    def export_logs(self):
        """Export logs to CSV file"""
        filename, _ = QFileDialog.getSaveFileName(self, "Export Logs", "", "CSV Files (*.csv)")
        if filename:
            self.logger.export_logs(filename)
            QMessageBox.information(self, "Success", f"Logs exported to {filename}")
            
    def clear_logs(self):
        """Clear all logs"""
        reply = QMessageBox.question(self, "Clear Logs", 
                                   "Are you sure you want to clear all logs?",
                                   QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.logger.clear_logs()
            self.load_logs()
            QMessageBox.information(self, "Success", "All logs cleared.")
            
    def update_security_score(self):
        """Update the security score display"""
        self.score_label.setText(f"Security Score: {self.security_score}")
        if self.security_score >= 80:
            color = "#2ecc71"  # Green
        elif self.security_score >= 60:
            color = "#f39c12"  # Orange
        else:
            color = "#e74c3c"  # Red
        self.score_label.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {color};")
        
    def show_alert(self, message, level="info"):
        """Show security alert"""
        if level == "warning":
            self.alerts_text.append(f"⚠️ {message}")
        elif level == "danger":
            self.alerts_text.append(f"🚨 {message}")
        else:
            self.alerts_text.append(f"ℹ️ {message}")
            
        # Auto-scroll to bottom
        scrollbar = self.alerts_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("WebSecGuard")
    app.setApplicationVersion("1.0")
    
    window = WebSecGuard()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main() 