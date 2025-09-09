import streamlit as st
from streamlit_option_menu import option_menu
import time
import random
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import numpy as np

# ---- PAGE CONFIG ----
st.set_page_config(
    page_title="ANGELSUCCESS - AI Cybersecurity Platform", 
    layout="wide",
    initial_sidebar_state="auto"
)

# ---- OPTIMIZED CSS ----
st.markdown("""
    <style>
    .stApp { background: linear-gradient(135deg, #f5f7fa 0%, #e4e7eb 50%, #f0f4f8 100%); }
    h1, h2, h3, h4, h5 { 
        background: linear-gradient(90deg, #0066cc 0%, #0099ff 50%, #0066cc 100%);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 700; 
    }
    .professional-container { 
        background: rgba(255, 255, 255, 0.95); border: 1px solid #e0e0e0; border-radius: 10px; 
        padding: 25px; margin-bottom: 25px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05); 
    }
    .stButton>button { 
        background: linear-gradient(90deg, #0066cc 0%, #0099ff 100%); color: white; border: none; 
        border-radius: 6px; padding: 12px 28px; font-weight: 600; 
    }
    </style>
""", unsafe_allow_html=True)

# ---- SESSION STATE INITIALIZATION ----
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "current_page" not in st.session_state:
    st.session_state.current_page = "Dashboard"
if "username" not in st.session_state:
    st.session_state.username = ""
if "threat_data" not in st.session_state:
    st.session_state.threat_data = None
if "initialized" not in st.session_state:
    st.session_state.initialized = False

# ---- LAZY LOADING UTILITY FUNCTIONS ----
@st.cache_data(ttl=300)
def generate_network_data():
    """Generate sample network traffic data"""
    timestamps = pd.date_range(end=pd.Timestamp.now(), periods=100, freq='min')
    return pd.DataFrame({
        'timestamp': timestamps,
        'bytes_sent': [random.randint(1000, 100000) for _ in range(100)],
        'bytes_received': [random.randint(1000, 50000) for _ in range(100)],
        'source_ip': [f"192.168.1.{random.randint(1, 50)}" for _ in range(100)],
        'destination_ip': [f"10.0.0.{random.randint(1, 20)}" for _ in range(100)],
        'protocol': [random.choice(['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']) for _ in range(100)]
    })

@st.cache_data(ttl=300)
def generate_threat_intel():
    """Generate sample threat intelligence data"""
    return pd.DataFrame({
        'threat_name': ['Trojan:Win32/Zpevdo', 'Ransom:Win32/Crowti', 'Exploit:Java/CVE-2012-1723', 
                        'Phishing:HTML/FakeBank', 'DDoS:UDP/Flood'],
        'severity': ['High', 'Critical', 'Medium', 'High', 'Critical'],
        'affected_systems': ['Windows OS', 'Multiple Platforms', 'Java Applications', 'Web Browsers', 'Network Infrastructure'],
        'first_detected': ['2023-10-15', '2023-10-14', '2023-10-13', '2023-10-12', '2023-10-11'],
        'status': ['Contained', 'Active', 'Patched', 'Monitoring', 'Mitigated']
    })

@st.cache_data(ttl=3600)
def generate_ai_models():
    """Generate sample AI model data"""
    return pd.DataFrame({
        'model_name': ['Anomaly Detection v3.2', 'Threat Classification v2.1', 'Behavior Analysis v4.0', 
                       'Predictive Defense v1.5', 'Zero-Day Detection v5.2'],
        'accuracy': [0.972, 0.956, 0.923, 0.889, 0.934],
        'precision': [0.961, 0.942, 0.911, 0.875, 0.921],
        'recall': [0.968, 0.951, 0.928, 0.882, 0.939],
        'status': ['Active', 'Active', 'Training', 'Active', 'Active']
    })

@st.cache_data(ttl=300)
def generate_vulnerability_data():
    """Generate sample vulnerability data"""
    return pd.DataFrame({
        'CVE ID': ['CVE-2023-1234', 'CVE-2023-5678', 'CVE-2023-9012', 'CVE-2023-3456', 'CVE-2023-7890'],
        'Severity': ['Critical', 'High', 'Medium', 'Low', 'High'],
        'Affected Systems': ['Windows Server', 'Apache Web Server', 'MySQL Database', 'Custom Application', 'Network Router'],
        'Published': ['2023-10-15', '2023-10-14', '2023-10-13', '2023-10-12', '2023-10-11'],
        'Status': ['Patched', 'In Progress', 'Not Started', 'Not Started', 'In Progress']
    })

@st.cache_data(ttl=300)
def generate_reports():
    """Generate sample report data"""
    return pd.DataFrame({
        'Report Name': ['Daily Threat Summary', 'Weekly Vulnerability Scan', 'Monthly Compliance Report', 
                        'Quarterly Security Audit', 'Annual Risk Assessment'],
        'Generated': ['2023-10-15 08:30', '2023-10-14 09:15', '2023-10-10 14:20', '2023-10-05 11:45', '2023-10-01 16:00'],
        'Status': ['Completed', 'Completed', 'Completed', 'In Progress', 'Scheduled'],
        'Download': ['📥 Download', '📥 Download', '📥 Download', '⏳ Processing', '📅 Schedule']
    })

def get_threat_data():
    if st.session_state.threat_data is None:
        dates = pd.date_range(end=pd.Timestamp.now(), periods=24, freq='H')
        st.session_state.threat_data = pd.DataFrame({
            'timestamp': dates,
            'threat_count': [random.randint(0, 20) for _ in range(24)],
            'threat_type': [random.choice(['DDoS', 'Malware', 'Phishing', 'Ransomware', 'Brute Force']) for _ in range(24)],
            'severity': [random.choice(['Low', 'Medium', 'High', 'Critical']) for _ in range(24)]
        })
    return st.session_state.threat_data

# ---- LANDING PAGE ----
if not st.session_state.logged_in:
    # Header Section
    col1, col2, col3 = st.columns([1, 3, 1])
    with col2:
        st.markdown("<h1 style='text-align: center; margin-bottom: 10px;'>🔐 ANGELSUCCESS</h1>", unsafe_allow_html=True)
        st.markdown("<h4 style='text-align: center; color: #666; margin-top: 0;'>AI-Powered Cybersecurity Threat Detection Platform</h4>", unsafe_allow_html=True)
    
    # Login Section
    st.markdown("<div style='max-width: 450px; margin: 0 auto; padding: 30px; background: rgba(255, 255, 255, 0.98); border-radius: 10px; border: 1px solid #e0e0e0; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);'>", unsafe_allow_html=True)
    login_col1, login_col2 = st.columns(2)
    
    with login_col1:
        st.subheader("Login to Dashboard")
        username = st.text_input("Username", placeholder="Enter your username", key="login_username")
        password = st.text_input("Password", type="password", placeholder="Enter your password", key="login_password")
        
        if st.button("Login", use_container_width=True):
            if username and password:
                with st.spinner("Authenticating..."):
                    time.sleep(1.5)
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.rerun()
            else:
                st.error("Please enter both username and password.")
    
    with login_col2:
        st.subheader("New Account")
        new_username = st.text_input("New Username", placeholder="Choose a username", key="new_username")
        new_email = st.text_input("Email", placeholder="Your email address", key="new_email")
        new_password = st.text_input("New Password", type="password", placeholder="Create a password", key="new_password")
        
        if st.button("Sign Up", use_container_width=True):
            if new_username and new_email and new_password:
                st.success("Account created successfully. Please login with your credentials.")
            else:
                st.warning("Please complete all fields to sign up.")
    
    st.markdown("</div>", unsafe_allow_html=True)
    
    # Stats counter
    st.markdown("<div style='height: 2px; background: linear-gradient(90deg, transparent 0%, #0066cc 50%, transparent 100%); margin: 40px 0;'></div>", unsafe_allow_html=True)
    stats_col1, stats_col2, stats_col3, stats_col4 = st.columns(4)
    with stats_col1:
        st.markdown("""
            <div style='text-align: center; padding: 20px;'>
                <div style='font-size: 2.5rem; font-weight: 700; background: linear-gradient(90deg, #0066cc 0%, #0099ff 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;'>500+</div>
                <div style='font-size: 0.9rem; color: #666; font-weight: 600;'>ENTERPRISES PROTECTED</div>
            </div>
        """, unsafe_allow_html=True)
    with stats_col2:
        st.markdown("""
            <div style='text-align: center; padding: 20px;'>
                <div style='font-size: 2.5rem; font-weight: 700; background: linear-gradient(90deg, #0066cc 0%, #0099ff 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;'>10M+</div>
                <div style='font-size: 0.9rem; color: #666; font-weight: 600;'>THREATS DETECTED DAILY</div>
            </div>
        """, unsafe_allow_html=True)
    with stats_col3:
        st.markdown("""
            <div style='text-align: center; padding: 20px;'>
                <div style='font-size: 2.5rem; font-weight: 700; background: linear-gradient(90deg, #0066cc 0%, #0099ff 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;'>99.9%</div>
                <div style='font-size: 0.9rem; color: #666; font-weight: 600;'>ACCURACY RATE</div>
            </div>
        """, unsafe_allow_html=True)
    with stats_col4:
        st.markdown("""
            <div style='text-align: center; padding: 20px;'>
                <div style='font-size: 2.5rem; font-weight: 700; background: linear-gradient(90deg, #0066cc 0%, #0099ff 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;'>24/7</div>
                <div style='font-size: 0.9rem; color: #666; font-weight: 600;'>REAL-TIME MONITORING</div>
            </div>
        """, unsafe_allow_html=True)
    
    # Only load heavy content if user requests it
    if not st.session_state.initialized:
        if st.button("Explore Platform Features", use_container_width=True):
            st.session_state.initialized = True
            st.rerun()
    else:
        # Load the rest of the landing page content only when requested
        st.markdown("<div style='height: 2px; background: linear-gradient(90deg, transparent 0%, #0066cc 50%, transparent 100%); margin: 40px 0;'></div>", unsafe_allow_html=True)
        
        # Platform Overview
        with st.container():
            st.header("🚀 Platform Overview")
            st.write("""
            ANGELSUCCESS is an advanced AI-powered cybersecurity platform that provides comprehensive protection 
            against modern cyber threats. Our platform combines cutting-edge artificial intelligence, machine learning, 
            and data analytics to deliver real-time threat detection, prevention, and response capabilities.
            """)
            
            overview_col1, overview_col2, overview_col3 = st.columns(3)
            with overview_col1:
                st.markdown("**🔍 Real-time Monitoring**")
                st.markdown("Continuous surveillance of network activities with AI-powered anomaly detection.")
            with overview_col2:
                st.markdown("**🤖 Automated Response**")
                st.markdown("Instant mitigation actions triggered by our intelligent defense systems.")
            with overview_col3:
                st.markdown("**📊 Advanced Analytics**")
                st.markdown("Deep insights into security posture with comprehensive reporting tools.")
        
        if st.button("Show Less", use_container_width=True):
            st.session_state.initialized = False
            st.rerun()

# ---- DASHBOARD (Logged In) ----
else:
    # Apply dashboard styling
    st.markdown("""
        <style>
        .stApp { background: #0e1117; color: #fafafa; }
        </style>
    """, unsafe_allow_html=True)
    
    # Sidebar navigation with streamlit_option_menu
    with st.sidebar:
        st.title(f"🔐 Welcome, {st.session_state.username}")
        st.markdown("---")
        
        selected = option_menu(
            menu_title="Navigation",
            options=["Dashboard", "Threat Detection", "Network Analysis", "Vulnerability Management", "Reports", "Settings"],
            icons=["speedometer2", "shield-shaded", "diagram-3", "bug", "clipboard-data", "gear"],
            default_index=0,
            styles={
                "container": {"padding": "5px", "background-color": "#1a1a2e"},
                "icon": {"color": "#00d4ff", "font-size": "18px"},
                "nav-link": {"color": "#f0f0f0", "font-size": "16px", "text-align": "left", "margin": "0px"},
                "nav-link-selected": {"background-color": "#0066cc"},
            }
        )
        
        st.session_state.current_page = selected
        
        st.markdown("---")
        st.markdown("**System Status**")
        st.markdown("🟢 **Data Ingestion:** Active")
        st.markdown("🟡 **ML Models:** 2/3 Trained")
        st.markdown("🟢 **Alert System:** Active")
        st.markdown("🟢 **Threat Intelligence:** Updated")
        
        st.markdown("---")
        st.markdown("**Last Update:** " + datetime.now().strftime("%H:%M:%S"))
        
        if st.button("Logout", use_container_width=True):
            st.session_state.logged_in = False
            st.session_state.initialized = False
            st.rerun()
    
    # Main content area based on selected page
    if st.session_state.current_page == "Dashboard":
        st.title("📊 Security Dashboard")
        
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Data Ingestion Rate", "12.5K/min", "2.1%")
        with col2:
            st.metric("Anomalies Detected", "42", "5")
        with col3:
            st.metric("Threats Identified", "8", "-2")
        with col4:
            st.metric("Active Alerts", "3", "1")
        
        st.markdown("---")
        
        # Threat timeline chart
        st.subheader("Threat Detection Timeline")
        threat_data = get_threat_data()
        fig = px.line(threat_data, x='timestamp', y='threat_count', 
                      title='Threats Detected Over Time', markers=True)
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
        
        # System status and recent alerts
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("System Status")
            st.markdown("🟢 **Data Ingestion:** Active")
            st.markdown("🟡 **ML Models:** 2/3 Trained")
            st.markdown("🟢 **Alert System:** Active")
            st.markdown("🟢 **Threat Intelligence:** Updated")
        
        with col2:
            st.subheader("Recent Alerts")
            alert_data = pd.DataFrame({
                'Time': ['10:23:45', '10:15:32', '09:58:12'],
                'Severity': ['High', 'Medium', 'Critical'],
                'Type': ['Suspicious Login', 'Port Scan', 'Multiple Failed Attempts'],
                'Status': ['Investigating', 'Resolved', 'Investigating']
            })
            st.dataframe(alert_data, use_container_width=True, hide_index=True)
    
    elif st.session_state.current_page == "Threat Detection":
        st.title("🔍 Threat Detection")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Active Threats")
            threat_data = generate_threat_intel()
            st.dataframe(threat_data, use_container_width=True, hide_index=True)
        
        with col2:
            st.subheader("Threat Severity Distribution")
            threat_data = get_threat_data()
            severity_counts = threat_data['severity'].value_counts()
            fig = px.pie(values=severity_counts.values, names=severity_counts.index, 
                         title='Threats by Severity Level')
            st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("Threat Type Analysis")
        threat_type_counts = threat_data['threat_type'].value_counts()
        fig = px.bar(x=threat_type_counts.index, y=threat_type_counts.values, 
                     title='Threats by Type', labels={'x': 'Threat Type', 'y': 'Count'})
        st.plotly_chart(fig, use_container_width=True)
    
    elif st.session_state.current_page == "Network Analysis":
        st.title("🌐 Network Analysis")
        
        network_data = generate_network_data()
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Network Traffic Overview")
            fig = px.line(network_data, x='timestamp', y=['bytes_sent', 'bytes_received'],
                         title='Network Traffic Over Time', labels={'value': 'Bytes', 'variable': 'Traffic Type'})
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("Protocol Distribution")
            protocol_counts = network_data['protocol'].value_counts()
            fig = px.pie(values=protocol_counts.values, names=protocol_counts.index,
                        title='Network Traffic by Protocol')
            st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("Top Source IP Addresses")
        source_ip_counts = network_data['source_ip'].value_counts().head(10)
        fig = px.bar(x=source_ip_counts.index, y=source_ip_counts.values,
                    title='Top 10 Source IP Addresses', labels={'x': 'IP Address', 'y': 'Connection Count'})
        st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("Raw Network Data")
        st.dataframe(network_data.tail(20), use_container_width=True)

    elif st.session_state.current_page == "Vulnerability Management":
        st.title("🐛 Vulnerability Management")
        
        vuln_data = generate_vulnerability_data()
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Vulnerability Overview")
            st.dataframe(vuln_data, use_container_width=True, hide_index=True)
        
        with col2:
            st.subheader("Vulnerability Severity")
            severity_counts = vuln_data['Severity'].value_counts()
            fig = px.pie(values=severity_counts.values, names=severity_counts.index,
                        title='Vulnerabilities by Severity Level')
            st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("Remediation Status")
        status_counts = vuln_data['Status'].value_counts()
        fig = px.bar(x=status_counts.index, y=status_counts.values,
                    title='Vulnerability Remediation Status', labels={'x': 'Status', 'y': 'Count'})
        st.plotly_chart(fig, use_container_width=True)
        
        # Vulnerability scanner
        st.subheader("Run Vulnerability Scan")
        scan_target = st.selectbox("Select target to scan", 
                                 ['All Systems', 'Web Servers', 'Database Servers', 'Network Devices', 'Endpoints'])
        
        if st.button("Start Scan", use_container_width=True):
            with st.spinner(f"Scanning {scan_target}..."):
                progress_bar = st.progress(0)
                for percent_complete in range(100):
                    time.sleep(0.02)
                    progress_bar.progress(percent_complete + 1)
                
                st.success(f"Scan completed! Found {random.randint(0, 15)} potential vulnerabilities.")
                st.info("Review findings in the vulnerability overview above.")

    elif st.session_state.current_page == "Reports":
        st.title("📊 Reports & Analytics")
        
        report_data = generate_reports()
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Available Reports")
            st.dataframe(report_data, use_container_width=True, hide_index=True)
        
        with col2:
            st.subheader("Custom Report Generator")
            report_type = st.selectbox("Report Type", 
                                     ['Threat Summary', 'Vulnerability Assessment', 'Compliance', 'Incident Response', 'Audit Trail'])
            
            date_range = st.date_input("Date Range", 
                                     [datetime.now() - timedelta(days=7), datetime.now()])
            
            format_type = st.radio("Export Format", ['PDF', 'CSV', 'Excel', 'HTML'])
            
            if st.button("Generate Report", use_container_width=True):
                with st.spinner("Generating report..."):
                    time.sleep(2)
                    st.success(f"{report_type} report generated successfully!")
                    st.download_button(
                        label=f"Download {format_type} Report",
                        data="Sample report content - this would be actual report data in a real application",
                        file_name=f"{report_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format_type.lower()}",
                        mime="text/plain" if format_type != 'PDF' else "application/pdf"
                    )
        
        # Security metrics dashboard
        st.subheader("Security Metrics Dashboard")
        
        metrics_col1, metrics_col2, metrics_col3, metrics_col4 = st.columns(4)
        with metrics_col1:
            st.metric("MTTD", "15min", "-5min")
        with metrics_col2:
            st.metric("MTTR", "45min", "+10min")
        with metrics_col3:
            st.metric("False Positives", "12%", "-3%")
        with metrics_col4:
            st.metric("Coverage", "98%", "2%")

    elif st.session_state.current_page == "Settings":
        st.title("⚙️ Settings & Configuration")
        
        tab1, tab2, tab3 = st.tabs(["User Preferences", "System Configuration", "Alert Settings"])
        
        with tab1:
            st.subheader("User Preferences")
            
            col1, col2 = st.columns(2)
            with col1:
                st.text_input("Full Name", value=st.session_state.username)
                st.text_input("Email", value=f"{st.session_state.username}@company.com")
                st.selectbox("Timezone", ["UTC", 'EST', 'PST', 'GMT'])
            
            with col2:
                st.selectbox("Theme", ["Dark", "Light", "System Default"])
                st.slider("Dashboard Refresh Rate (seconds)", 30, 300, 60)
                st.checkbox("Email Notifications")
            
            if st.button("Save Preferences", use_container_width=True):
                st.success("Preferences saved successfully!")
        
        with tab2:
            st.subheader("System Configuration")
            
            st.selectbox("Data Retention Policy", ["30 days", "60 days", "90 days", "1 year"])
            st.slider("Log Level", 1, 5, 3)
            
            col1, col2 = st.columns(2)
            with col1:
                st.checkbox("Enable Auto Updates")
                st.checkbox("Enable Backup")
            
            with col2:
                st.checkbox("Enable Cloud Sync")
                st.checkbox("Enable Diagnostic Data")
            
            if st.button("Save Configuration", use_container_width=True):
                st.success("System configuration updated!")
        
        with tab3:
            st.subheader("Alert Settings")
            
            st.slider("Critical Alert Threshold", 1, 100, 80)
            st.slider("High Alert Threshold", 1, 100, 60)
            st.slider("Medium Alert Threshold", 1, 100, 40)
            
            st.multiselect("Alert Channels", 
                          ["Email", "SMS", "Push Notification", "Slack", "Teams"],
                          default=["Email", "Push Notification"])
            
            if st.button("Save Alert Settings", use_container_width=True):
                st.success("Alert settings updated!")
