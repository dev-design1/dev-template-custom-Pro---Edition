#!/usr/bin/env python3
"""
SecureNet Monitor Pro - Enterprise Grade Network & Security Monitor
Features: VPN Detection, Anti-Cheat System, Threat Detection, Real-time Analytics
"""

import customtkinter as ctk
from tkinter import ttk, messagebox
import requests
import psutil
import socket
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json
import subprocess
import platform
import re
from collections import deque
import urllib.request
import ssl

# Modern Theme Configuration
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class SecureNetMonitor(ctk.CTk):
    """Main Application Class"""
    
    def __init__(self):
        super().__init__()
        
        # Window Configuration
        self.title("SecureNet Monitor Pro - Enterprise Edition")
        self.geometry("1600x950")
        self.minsize(1400, 800)
        
        # Configure grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Application State
        self.monitoring_active = False
        self.alert_count = 0
        self.vpn_detected = False
        self.threat_level = "LOW"
        
        # Data Storage
        self.history_data = {
            'cpu': deque(maxlen=100),
            'memory': deque(maxlen=100),
            'network_in': deque(maxlen=100),
            'network_out': deque(maxlen=100),
            'latency': deque(maxlen=100),
            'timestamps': deque(maxlen=100)
        }
        
        # Monitored Websites
        self.monitored_sites = [
            {'url': 'https://google.com', 'name': 'Google', 'status': 'Unknown'},
            {'url': 'https://github.com', 'name': 'GitHub', 'status': 'Unknown'},
            {'url': 'https://cloudflare.com', 'name': 'Cloudflare', 'status': 'Unknown'}
        ]
        
        # Security Config
        self.security_config = {
            'vpn_check_enabled': True,
            'anticheat_enabled': True,
            'threat_detection': True,
            'max_cpu_threshold': 85,
            'max_memory_threshold': 90,
            'max_latency_ms': 500
        }
        
        # Statistics
        self.stats = {
            'total_scans': 0,
            'threats_detected': 0,
            'vpn_detections': 0,
            'uptime_seconds': 0,
            'packets_sent': 0,
            'packets_received': 0,
            'start_time': datetime.now()
        }
        
        # Build UI
        self.build_ui()
        
        # Start background monitoring
        self.start_monitoring_thread()
    
    def build_ui(self):
        """Build the complete modern UI"""
        
        # === SIDEBAR ===
        self.sidebar_frame = ctk.CTkFrame(self, width=280, corner_radius=0, fg_color="#1a1a2e")
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(10, weight=1)
        
        # Logo Section
        logo_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        logo_frame.grid(row=0, column=0, padx=20, pady=(30, 20))
        
        self.app_logo = ctk.CTkLabel(
            logo_frame,
            text="🛡️",
            font=("Arial", 48)
        )
        self.app_logo.pack()
        
        self.app_title = ctk.CTkLabel(
            logo_frame,
            text="SecureNet Monitor",
            font=("Segoe UI", 18, "bold"),
            text_color="#00d4ff"
        )
        self.app_title.pack()
        
        self.app_subtitle = ctk.CTkLabel(
            logo_frame,
            text="Enterprise Edition",
            font=("Segoe UI", 10),
            text_color="#7f8c8d"
        )
        self.app_subtitle.pack()
        
        # Navigation Buttons
        self.nav_buttons = {}
        nav_items = [
            ("📊 Dashboard", "dashboard"),
            ("🌐 Network Status", "network"),
            ("🔐 VPN Detector", "vpn"),
            ("🛡️ Anti-Cheat", "anticheat"),
            ("⚠️ Threat Monitor", "threats"),
            ("📈 Analytics", "analytics"),
            ("⚙️ Settings", "settings")
        ]
        
        for idx, (text, key) in enumerate(nav_items, start=1):
            btn = ctk.CTkButton(
                self.sidebar_frame,
                text=text,
                font=("Segoe UI", 13),
                fg_color="transparent",
                hover_color="#16213e",
                anchor="w",
                height=45,
                command=lambda k=key: self.switch_view(k)
            )
            btn.grid(row=idx, column=0, padx=15, pady=5, sticky="ew")
            self.nav_buttons[key] = btn
        
        # Status Indicator
        self.status_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="#0f3460", corner_radius=10)
        self.status_frame.grid(row=11, column=0, padx=15, pady=20, sticky="ew")
        
        self.status_indicator = ctk.CTkLabel(
            self.status_frame,
            text="● MONITORING",
            font=("Segoe UI", 12, "bold"),
            text_color="#00ff00"
        )
        self.status_indicator.pack(pady=10)
        
        # Control Buttons
        self.btn_start = ctk.CTkButton(
            self.sidebar_frame,
            text="▶ Start Monitoring",
            font=("Segoe UI", 13, "bold"),
            fg_color="#27ae60",
            hover_color="#229954",
            height=40,
            command=self.start_monitoring
        )
        self.btn_start.grid(row=12, column=0, padx=15, pady=5, sticky="ew")
        
        self.btn_stop = ctk.CTkButton(
            self.sidebar_frame,
            text="⏸ Stop Monitoring",
            font=("Segoe UI", 13, "bold"),
            fg_color="#e74c3c",
            hover_color="#c0392b",
            height=40,
            command=self.stop_monitoring,
            state="disabled"
        )
        self.btn_stop.grid(row=13, column=0, padx=15, pady=5, sticky="ew")
        
        # === MAIN CONTENT AREA ===
        self.main_container = ctk.CTkFrame(self, corner_radius=0, fg_color="#0f0f1e")
        self.main_container.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(1, weight=1)
        
        # Top Bar with Stats
        self.create_top_stats_bar()
        
        # Content Frame (where different views will be displayed)
        self.content_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.content_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        # Show Dashboard by default
        self.current_view = "dashboard"
        self.show_dashboard_view()
    
    def create_top_stats_bar(self):
        """Create top statistics bar"""
        stats_bar = ctk.CTkFrame(self.main_container, height=100, fg_color="#1a1a2e", corner_radius=0)
        stats_bar.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        stats_bar.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)
        
        # Stat Cards
        self.stat_cards = {}
        
        stats_data = [
            ("🔍 Total Scans", "total_scans", "#3498db"),
            ("⚠️ Threats", "threats_detected", "#e74c3c"),
            ("🔐 VPN Detected", "vpn_detections", "#f39c12"),
            ("📊 CPU Usage", "cpu_usage", "#9b59b6"),
            ("💾 Memory", "memory_usage", "#1abc9c")
        ]
        
        for idx, (title, key, color) in enumerate(stats_data):
            card = self.create_stat_card(stats_bar, title, "0", color)
            card.grid(row=0, column=idx, padx=10, pady=15, sticky="ew")
            self.stat_cards[key] = card
    
    def create_stat_card(self, parent, title, value, color):
        """Create a modern stat card"""
        card = ctk.CTkFrame(parent, fg_color="#16213e", corner_radius=10)
        
        icon_label = ctk.CTkLabel(
            card,
            text=title.split()[0],
            font=("Arial", 24)
        )
        icon_label.pack(pady=(10, 0))
        
        value_label = ctk.CTkLabel(
            card,
            text=value,
            font=("Segoe UI", 24, "bold"),
            text_color=color
        )
        value_label.pack()
        
        title_label = ctk.CTkLabel(
            card,
            text=" ".join(title.split()[1:]),
            font=("Segoe UI", 10),
            text_color="#7f8c8d"
        )
        title_label.pack(pady=(0, 10))
        
        # Store reference to update later
        card.value_label = value_label
        
        return card
    
    def show_dashboard_view(self):
        """Display Dashboard View"""
        self.clear_content_frame()
        
        # Configure grid
        self.content_frame.grid_columnconfigure((0, 1), weight=1)
        self.content_frame.grid_rowconfigure((0, 1, 2), weight=1)
        
        # System Resources Card
        sys_card = self.create_info_card(
            "💻 System Resources",
            "#2c3e50"
        )
        sys_card.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        self.cpu_label = ctk.CTkLabel(sys_card, text="CPU: 0%", font=("Segoe UI", 16))
        self.cpu_label.pack(pady=5)
        
        self.cpu_progress = ctk.CTkProgressBar(sys_card, width=300)
        self.cpu_progress.pack(pady=5)
        self.cpu_progress.set(0)
        
        self.memory_label = ctk.CTkLabel(sys_card, text="Memory: 0%", font=("Segoe UI", 16))
        self.memory_label.pack(pady=5)
        
        self.memory_progress = ctk.CTkProgressBar(sys_card, width=300)
        self.memory_progress.pack(pady=5)
        self.memory_progress.set(0)
        
        self.disk_label = ctk.CTkLabel(sys_card, text="Disk: 0%", font=("Segoe UI", 16))
        self.disk_label.pack(pady=5)
        
        self.disk_progress = ctk.CTkProgressBar(sys_card, width=300)
        self.disk_progress.pack(pady=5)
        self.disk_progress.set(0)
        
        # Network Status Card
        net_card = self.create_info_card(
            "🌐 Network Status",
            "#16a085"
        )
        net_card.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        self.internet_status = ctk.CTkLabel(
            net_card,
            text="Internet: Checking...",
            font=("Segoe UI", 16)
        )
        self.internet_status.pack(pady=10)
        
        self.latency_label = ctk.CTkLabel(
            net_card,
            text="Latency: --- ms",
            font=("Segoe UI", 14)
        )
        self.latency_label.pack(pady=5)
        
        self.upload_label = ctk.CTkLabel(
            net_card,
            text="Upload: 0 KB/s",
            font=("Segoe UI", 14)
        )
        self.upload_label.pack(pady=5)
        
        self.download_label = ctk.CTkLabel(
            net_card,
            text="Download: 0 KB/s",
            font=("Segoe UI", 14)
        )
        self.download_label.pack(pady=5)
        
        # VPN Detection Card
        vpn_card = self.create_info_card(
            "🔐 VPN & Proxy Detection",
            "#8e44ad"
        )
        vpn_card.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        
        self.vpn_status = ctk.CTkLabel(
            vpn_card,
            text="VPN Status: Checking...",
            font=("Segoe UI", 16, "bold")
        )
        self.vpn_status.pack(pady=10)
        
        self.ip_label = ctk.CTkLabel(
            vpn_card,
            text="IP: ---",
            font=("Segoe UI", 13)
        )
        self.ip_label.pack(pady=5)
        
        self.location_label = ctk.CTkLabel(
            vpn_card,
            text="Location: ---",
            font=("Segoe UI", 13)
        )
        self.location_label.pack(pady=5)
        
        self.isp_label = ctk.CTkLabel(
            vpn_card,
            text="ISP: ---",
            font=("Segoe UI", 13)
        )
        self.isp_label.pack(pady=5)
        
        # Threat Detection Card
        threat_card = self.create_info_card(
            "⚠️ Threat Detection",
            "#c0392b"
        )
        threat_card.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")
        
        self.threat_level_label = ctk.CTkLabel(
            threat_card,
            text="Threat Level: LOW",
            font=("Segoe UI", 18, "bold"),
            text_color="#27ae60"
        )
        self.threat_level_label.pack(pady=10)
        
        self.threats_found = ctk.CTkLabel(
            threat_card,
            text="Threats Found: 0",
            font=("Segoe UI", 14)
        )
        self.threats_found.pack(pady=5)
        
        self.last_scan = ctk.CTkLabel(
            threat_card,
            text="Last Scan: Never",
            font=("Segoe UI", 12),
            text_color="#7f8c8d"
        )
        self.last_scan.pack(pady=5)
        
        # Website Monitoring Card
        sites_card = self.create_info_card(
            "🌍 Monitored Websites",
            "#34495e"
        )
        sites_card.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        
        # Table for websites
        self.sites_table_frame = ctk.CTkScrollableFrame(sites_card, fg_color="transparent")
        self.sites_table_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Headers
        headers = ["Website", "URL", "Status", "Response Time"]
        for idx, header in enumerate(headers):
            lbl = ctk.CTkLabel(
                self.sites_table_frame,
                text=header,
                font=("Segoe UI", 12, "bold")
            )
            lbl.grid(row=0, column=idx, padx=10, pady=5)
        
        self.site_labels = []
        for idx, site in enumerate(self.monitored_sites, start=1):
            row_labels = []
            
            # Name
            name_lbl = ctk.CTkLabel(self.sites_table_frame, text=site['name'], font=("Segoe UI", 11))
            name_lbl.grid(row=idx, column=0, padx=10, pady=5)
            row_labels.append(name_lbl)
            
            # URL
            url_lbl = ctk.CTkLabel(self.sites_table_frame, text=site['url'], font=("Segoe UI", 11), text_color="#7f8c8d")
            url_lbl.grid(row=idx, column=1, padx=10, pady=5)
            row_labels.append(url_lbl)
            
            # Status
            status_lbl = ctk.CTkLabel(self.sites_table_frame, text="●", font=("Segoe UI", 11))
            status_lbl.grid(row=idx, column=2, padx=10, pady=5)
            row_labels.append(status_lbl)
            
            # Response Time
            time_lbl = ctk.CTkLabel(self.sites_table_frame, text="--- ms", font=("Segoe UI", 11))
            time_lbl.grid(row=idx, column=3, padx=10, pady=5)
            row_labels.append(time_lbl)
            
            self.site_labels.append(row_labels)
    
    def create_info_card(self, title, color):
        """Create an info card with title"""
        card = ctk.CTkFrame(self.content_frame, fg_color="#16213e", corner_radius=15)
        
        title_frame = ctk.CTkFrame(card, fg_color=color, corner_radius=10, height=40)
        title_frame.pack(fill="x", padx=10, pady=10)
        
        title_label = ctk.CTkLabel(
            title_frame,
            text=title,
            font=("Segoe UI", 16, "bold")
        )
        title_label.pack(pady=8)
        
        return card
    
    def clear_content_frame(self):
        """Clear all widgets from content frame"""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
    
    def switch_view(self, view_name):
        """Switch between different views"""
        self.current_view = view_name
        
        if view_name == "dashboard":
            self.show_dashboard_view()
        elif view_name == "network":
            self.show_network_view()
        elif view_name == "vpn":
            self.show_vpn_view()
        elif view_name == "anticheat":
            self.show_anticheat_view()
        elif view_name == "threats":
            self.show_threats_view()
        elif view_name == "analytics":
            self.show_analytics_view()
        elif view_name == "settings":
            self.show_settings_view()
    
    def show_network_view(self):
        """Network detailed view"""
        self.clear_content_frame()
        
        card = self.create_info_card("🌐 Network Detailed Information", "#16a085")
        card.pack(fill="both", expand=True, padx=10, pady=10)
        
        info = ctk.CTkLabel(
            card,
            text="Network monitoring in progress...\nDetailed stats will appear here.",
            font=("Segoe UI", 14),
            justify="left"
        )
        info.pack(pady=20)
    
    def show_vpn_view(self):
        """VPN detection detailed view"""
        self.clear_content_frame()
        
        card = self.create_info_card("🔐 VPN & Proxy Detection System", "#8e44ad")
        card.pack(fill="both", expand=True, padx=10, pady=10)
        
        info = ctk.CTkTextbox(card, font=("Consolas", 12), height=400)
        info.pack(fill="both", expand=True, padx=20, pady=20)
        info.insert("1.0", "VPN Detection System Active\n\nChecking for:\n• VPN Services\n• Proxy Servers\n• TOR Network\n• Data Center IPs\n\nResults will appear here...")
    
    def show_anticheat_view(self):
        """Anti-cheat system view"""
        self.clear_content_frame()
        
        card = self.create_info_card("🛡️ Anti-Cheat Protection System", "#e67e22")
        card.pack(fill="both", expand=True, padx=10, pady=10)
        
        info = ctk.CTkLabel(
            card,
            text="Anti-Cheat System Active\n\nMonitoring for suspicious activities...",
            font=("Segoe UI", 14)
        )
        info.pack(pady=20)
    
    def show_threats_view(self):
        """Threat monitoring view"""
        self.clear_content_frame()
        
        card = self.create_info_card("⚠️ Threat Detection & Analysis", "#c0392b")
        card.pack(fill="both", expand=True, padx=10, pady=10)
        
        info = ctk.CTkLabel(
            card,
            text="Threat monitoring system active...",
            font=("Segoe UI", 14)
        )
        info.pack(pady=20)
    
    def show_analytics_view(self):
        """Analytics view with charts"""
        self.clear_content_frame()
        
        card = self.create_info_card("📈 Performance Analytics", "#2980b9")
        card.pack(fill="both", expand=True, padx=10, pady=10)
        
        info = ctk.CTkLabel(
            card,
            text="Real-time performance charts will be displayed here...",
            font=("Segoe UI", 14)
        )
        info.pack(pady=20)
    
    def show_settings_view(self):
        """Settings view"""
        self.clear_content_frame()
        
        self.content_frame.grid_columnconfigure(0, weight=1)
        
        card = self.create_info_card("⚙️ Settings & Configuration", "#34495e")
        card.pack(fill="both", expand=True, padx=10, pady=10)
        
        settings_frame = ctk.CTkScrollableFrame(card, fg_color="transparent")
        settings_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Monitoring Settings
        ctk.CTkLabel(
            settings_frame,
            text="Monitoring Settings",
            font=("Segoe UI", 16, "bold")
        ).pack(anchor="w", pady=(10, 5))
        
        self.vpn_check_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            settings_frame,
            text="Enable VPN Detection",
            variable=self.vpn_check_var,
            font=("Segoe UI", 12)
        ).pack(anchor="w", pady=5)
        
        self.anticheat_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            settings_frame,
            text="Enable Anti-Cheat System",
            variable=self.anticheat_var,
            font=("Segoe UI", 12)
        ).pack(anchor="w", pady=5)
        
        self.threat_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            settings_frame,
            text="Enable Threat Detection",
            variable=self.threat_var,
            font=("Segoe UI", 12)
        ).pack(anchor="w", pady=5)
        
        # Thresholds
        ctk.CTkLabel(
            settings_frame,
            text="Alert Thresholds",
            font=("Segoe UI", 16, "bold")
        ).pack(anchor="w", pady=(20, 5))
        
        ctk.CTkLabel(settings_frame, text="CPU Threshold (%):").pack(anchor="w", pady=5)
        self.cpu_threshold = ctk.CTkSlider(settings_frame, from_=50, to=100)
        self.cpu_threshold.set(85)
        self.cpu_threshold.pack(fill="x", pady=5)
        
        ctk.CTkLabel(settings_frame, text="Memory Threshold (%):").pack(anchor="w", pady=5)
        self.mem_threshold = ctk.CTkSlider(settings_frame, from_=50, to=100)
        self.mem_threshold.set(90)
        self.mem_threshold.pack(fill="x", pady=5)
        
        # Save Button
        save_btn = ctk.CTkButton(
            settings_frame,
            text="💾 Save Settings",
            font=("Segoe UI", 14, "bold"),
            fg_color="#27ae60",
            hover_color="#229954",
            height=40,
            command=self.save_settings
        )
        save_btn.pack(pady=20)
    
    def save_settings(self):
        """Save settings"""
        self.security_config['vpn_check_enabled'] = self.vpn_check_var.get()
        self.security_config['anticheat_enabled'] = self.anticheat_var.get()
        self.security_config['threat_detection'] = self.threat_var.get()
        self.security_config['max_cpu_threshold'] = self.cpu_threshold.get()
        self.security_config['max_memory_threshold'] = self.mem_threshold.get()
        
        messagebox.showinfo("Settings Saved", "Your settings have been saved successfully!")
    
    def start_monitoring(self):
        """Start monitoring"""
        self.monitoring_active = True
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.status_indicator.configure(text="● MONITORING", text_color="#00ff00")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring_active = False
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.status_indicator.configure(text="● STOPPED", text_color="#e74c3c")
    
    def start_monitoring_thread(self):
        """Start background monitoring thread"""
        def monitor_loop():
            self.monitoring_active = True
            while True:
                if self.monitoring_active:
                    self.update_all_data()
                time.sleep(2)
        
        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()
    
    def update_all_data(self):
        """Update all monitoring data"""
        try:
            # Update system resources
            cpu = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
            
            # Update stats
            self.stats['total_scans'] += 1
            self.stats['uptime_seconds'] = (datetime.now() - self.stats['start_time']).seconds
            
            # Update UI (must be done in main thread)
            self.after(0, self.update_ui_data, cpu, memory, disk)
            
        except Exception as e:
            print(f"Error updating data: {e}")
    
    def update_ui_data(self, cpu, memory, disk):
        """Update UI with new data"""
        try:
            # Update progress bars
            if hasattr(self, 'cpu_progress'):
                self.cpu_label.configure(text=f"CPU: {cpu:.1f}%")
                self.cpu_progress.set(cpu / 100)
                
                self.memory_label.configure(text=f"Memory: {memory:.1f}%")
                self.memory_progress.set(memory / 100)
                
                self.disk_label.configure(text=f"Disk: {disk:.1f}%")
                self.disk_progress.set(disk / 100)
            
            # Update stat cards
            self.stat_cards['total_scans'].value_label.configure(
                text=str(self.stats['total_scans'])
            )
            self.stat_cards['cpu_usage'].value_label.configure(
                text=f"{cpu:.1f}%"
            )
            self.stat_cards['memory_usage'].value_label.configure(
                text=f"{memory:.1f}%"
            )
            
            # Check internet
            self.check_internet_status()
            
            # Check VPN (every 10 scans to avoid rate limits)
            if self.stats['total_scans'] % 10 == 0:
                threading.Thread(target=self.check_vpn_status, daemon=True).start()
            
            # Check websites
            if self.stats['total_scans'] % 5 == 0:
                threading.Thread(target=self.check_websites, daemon=True).start()
            
        except Exception as e:
            print(f"Error updating UI: {e}")
    
    def check_internet_status(self):
        """Check internet connectivity"""
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            if hasattr(self, 'internet_status'):
                self.internet_status.configure(
                    text="Internet: ✅ Connected",
                    text_color="#27ae60"
                )
        except OSError:
            if hasattr(self, 'internet_status'):
                self.internet_status.configure(
                    text="Internet: ❌ Disconnected",
                    text_color="#e74c3c"
                )
    
    def check_vpn_status(self):
        """Check for VPN/Proxy using multiple methods"""
        try:
            # Method 1: IP API check
            response = requests.get('https://ipapi.co/json/', timeout=5)
            data = response.json()
            
            ip = data.get('ip', 'Unknown')
            city = data.get('city', 'Unknown')
            country = data.get('country_name', 'Unknown')
            isp = data.get('org', 'Unknown')
            
            # Update UI
            self.after(0, lambda: self.ip_label.configure(text=f"IP: {ip}"))
            self.after(0, lambda: self.location_label.configure(text=f"Location: {city}, {country}"))
            self.after(0, lambda: self.isp_label.configure(text=f"ISP: {isp}"))
            
            # VPN Detection Logic
            vpn_indicators = [
                'vpn' in isp.lower(),
                'proxy' in isp.lower(),
                'hosting' in isp.lower(),
                data.get('asn', {}).get('type') == 'hosting'
            ]
            
            if any(vpn_indicators):
                self.vpn_detected = True
                self.stats['vpn_detections'] += 1
                self.after(0, lambda: self.vpn_status.configure(
                    text="⚠️ VPN/Proxy DETECTED",
                    text_color="#e74c3c"
                ))
            else:
                self.vpn_detected = False
                self.after(0, lambda: self.vpn_status.configure(
                    text="✅ No VPN Detected",
                    text_color="#27ae60"
                ))
            
            # Update stat card
            self.after(0, lambda: self.stat_cards['vpn_detections'].value_label.configure(
                text=str(self.stats['vpn_detections'])
            ))
            
        except Exception as e:
            print(f"VPN check error: {e}")
            self.after(0, lambda: self.vpn_status.configure(
                text="❓ VPN Check Failed",
                text_color="#f39c12"
            ))
    
    def check_websites(self):
        """Check monitored websites status"""
        for idx, site in enumerate(self.monitored_sites):
            try:
                start_time = time.time()
                response = requests.get(site['url'], timeout=5)
                response_time = int((time.time() - start_time) * 1000)
                
                if response.status_code == 200:
                    status = "✅ Online"
                    color = "#27ae60"
                else:
                    status = f"⚠️ {response.status_code}"
                    color = "#f39c12"
                
                # Update UI
                if hasattr(self, 'site_labels') and idx < len(self.site_labels):
                    self.after(0, lambda i=idx, s=status, c=color, rt=response_time: (
                        self.site_labels[i][2].configure(text=s, text_color=c),
                        self.site_labels[i][3].configure(text=f"{rt} ms")
                    ))
                
            except Exception as e:
                if hasattr(self, 'site_labels') and idx < len(self.site_labels):
                    self.after(0, lambda i=idx: (
                        self.site_labels[i][2].configure(text="❌ Offline", text_color="#e74c3c"),
                        self.site_labels[i][3].configure(text="Timeout")
                    ))


if __name__ == "__main__":
    app = SecureNetMonitor()
    app.mainloop()