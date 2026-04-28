"""Streamlit dashboard for MergenSec vulnerability mapping framework."""

import json
import os
import time
from datetime import datetime
from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Add parent directory to path for imports
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.vuln_mapper import map_vulnerability, classify_risk

# Page configuration
st.set_page_config(
    page_title="MergenSec - Vulnerability Mapping",
    page_icon="🏹",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        margin-bottom: 1rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        border-radius: 10px;
        padding: 15px;
        text-align: center;
    }
    .risk-critical {
        color: #dc2626;
        font-weight: bold;
    }
    .risk-high {
        color: #ea580c;
        font-weight: bold;
    }
    .risk-medium {
        color: #ca8a04;
        font-weight: bold;
    }
    .risk-low {
        color: #16a34a;
        font-weight: bold;
    }
    .stAlert {
        padding: 10px;
    }
</style>
""", unsafe_allow_html=True)


def load_sample_data() -> list[dict[str, Any]]:
    """Load sample vulnerability data for demonstration."""
    return [
        {
            "port": 80,
            "service": "http",
            "cve": "CVE-2021-41773",
            "description": "Apache Path Traversal",
            "cvss": 7.5,
            "risk": "HIGH"
        },
        {
            "port": 22,
            "service": "ssh",
            "cve": "CVE-2018-15473",
            "description": "OpenSSH User Enumeration",
            "cvss": 5.3,
            "risk": "MEDIUM"
        },
        {
            "port": 21,
            "service": "ftp",
            "cve": "CVE-2015-3306",
            "description": "ProFTPd Remote Code Execution",
            "cvss": 9.8,
            "risk": "HIGH"
        },
        {
            "port": 443,
            "service": "https",
            "cve": "CVE-2022-3602",
            "description": "OpenSSL Buffer Overflow",
            "cvss": 9.8,
            "risk": "HIGH"
        },
        {
            "port": 3306,
            "service": "mysql",
            "cve": "CVE-2016-6662",
            "description": "MySQL Remote Code Execution",
            "cvss": 9.8,
            "risk": "HIGH"
        },
        {
            "port": 8080,
            "service": "http-proxy",
            "cve": "CVE-2020-1147",
            "description": "Liferay Portal RCE",
            "cvss": 7.3,
            "risk": "HIGH"
        },
        {
            "port": 25,
            "service": "smtp",
            "cve": "CVE-2018-19433",
            "description": "Exim Mail Server RCE",
            "cvss": 8.0,
            "risk": "HIGH"
        },
        {
            "port": 53,
            "service": "dns",
            "cve": "CVE-2020-1350",
            "description": "Windows DNS Server RCE",
            "cvss": 8.8,
            "risk": "HIGH"
        }
    ]


def simulate_scan(target: str, ports: list[int]) -> list[dict[str, Any]]:
    """Simulate a network scan and return vulnerability results."""
    results = []
    
    for port in ports:
        # Simulate scan delay
        time.sleep(0.1)
        
        vuln = map_vulnerability(port)
        if vuln:
            results.append(vuln)
    
    return results


def display_metrics(results: list[dict[str, Any]]) -> None:
    """Display key metrics in cards."""
    if not results:
        st.info("No vulnerabilities found.")
        return
    
    # Calculate metrics
    total_vulns = len(results)
    critical_count = sum(1 for r in results if r["cvss"] >= 9.0)
    high_count = sum(1 for r in results if 7.0 <= r["cvss"] < 9.0)
    medium_count = sum(1 for r in results if 4.0 <= r["cvss"] < 7.0)
    low_count = sum(1 for r in results if r["cvss"] < 4.0)
    
    avg_cvss = sum(r["cvss"] for r in results) / total_vulns if results else 0
    
    # Display metrics in columns
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            label="Total Vulnerabilities",
            value=total_vulns,
            delta=None
        )
    
    with col2:
        st.metric(
            label="Critical",
            value=critical_count,
            delta_color="inverse" if critical_count > 0 else "normal"
        )
    
    with col3:
        st.metric(
            label="High",
            value=high_count,
            delta_color="inverse" if high_count > 0 else "normal"
        )
    
    with col4:
        st.metric(
            label="Medium",
            value=medium_count,
        )
    
    with col5:
        st.metric(
            label="Avg. CVSS",
            value=f"{avg_cvss:.1f}",
            delta=f"Risk Score"
        )


def display_risk_distribution(results: list[dict[str, Any]], key: str = "default") -> None:
    """Display risk distribution chart."""
    if not results:
        return
    
    # Count by risk level
    risk_counts = {
        "Critical": sum(1 for r in results if r["cvss"] >= 9.0),
        "High": sum(1 for r in results if 7.0 <= r["cvss"] < 9.0),
        "Medium": sum(1 for r in results if 4.0 <= r["cvss"] < 7.0),
        "Low": sum(1 for r in results if r["cvss"] < 4.0)
    }
    
    # Create pie chart
    fig = go.Figure(data=[go.Pie(
        labels=list(risk_counts.keys()),
        values=list(risk_counts.values()),
        hole=0.4,
        marker=dict(
            colors=["#dc2626", "#ea580c", "#ca8a04", "#16a34a"]
        )
    )])
    
    fig.update_layout(
        title="Risk Distribution",
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.2,
            xanchor="center",
            x=0.5
        )
    )
    
    st.plotly_chart(fig, use_container_width=True, key=f"risk_dist_{key}")


def display_cvss_histogram(results: list[dict[str, Any]], key: str = "default") -> None:
    """Display CVSS score histogram."""
    if not results:
        return
    
    cvss_scores = [r["cvss"] for r in results]
    
    fig = px.histogram(
        x=cvss_scores,
        nbins=10,
        labels={"x": "CVSS Score", "y": "Count"},
        color_discrete_sequence=["#1f77b4"]
    )
    
    fig.update_layout(
        title="CVSS Score Distribution",
        showlegend=False,
        bargap=0.1
    )
    
    st.plotly_chart(fig, use_container_width=True, key=f"cvss_hist_{key}")


def display_vulnerability_table(results: list[dict[str, Any]]) -> None:
    """Display vulnerability results in an interactive table."""
    if not results:
        st.info("No vulnerabilities found.")
        return
    
    # Create DataFrame
    df = pd.DataFrame(results)
    
    # Reorder columns
    df = df[["port", "service", "cve", "description", "cvss", "risk"]]
    
    # Add risk class for styling
    def get_risk_class(risk):
        if risk == "HIGH" and df.loc[df["risk"] == risk, "cvss"].max() >= 9.0:
            return "Critical"
        return risk
    
    df["risk_level"] = df.apply(lambda row: get_risk_class(row["risk"]), axis=1)
    
    # Display table with filtering
    st.subheader("Vulnerability Details")
    
    # Filter by risk level
    risk_filter = st.multiselect(
        "Filter by Risk Level",
        options=["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"]
    )
    
    filtered_df = df[df["risk_level"].isin(risk_filter)]
    
    # Display styled table
    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "port": st.column_config.NumberColumn("Port", format="%d"),
            "service": st.column_config.TextColumn("Service"),
            "cve": st.column_config.TextColumn("CVE ID"),
            "description": st.column_config.TextColumn("Description"),
            "cvss": st.column_config.NumberColumn("CVSS", format="%.1f"),
            "risk": st.column_config.TextColumn("Risk"),
            "risk_level": st.column_config.TextColumn("Risk Level")
        }
    )
    
    # Show details for selected CVE
    if not filtered_df.empty:
        st.subheader("CVE Details")
        selected_cve = st.selectbox(
            "Select a CVE to view details",
            options=filtered_df["cve"].unique()
        )
        
        if selected_cve:
            cve_data = filtered_df[filtered_df["cve"] == selected_cve].iloc[0]
            
            with st.expander(f"CVE Details: {selected_cve}", expanded=True):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Port:** {cve_data['port']}")
                    st.write(f"**Service:** {cve_data['service']}")
                    st.write(f"**CVSS Score:** {cve_data['cvss']}")
                
                with col2:
                    st.write(f"**Risk Level:** {cve_data['risk']}")
                    st.write(f"**Description:** {cve_data['description']}")


def generate_report(results: list[dict[str, Any]], target: str) -> dict[str, Any]:
    """Generate a JSON report of scan results."""
    report = {
        "scan_info": {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "tool": "MergenSec",
            "version": "1.0.0"
        },
        "summary": {
            "total_vulnerabilities": len(results),
            "critical_count": sum(1 for r in results if r["cvss"] >= 9.0),
            "high_count": sum(1 for r in results if 7.0 <= r["cvss"] < 9.0),
            "medium_count": sum(1 for r in results if 4.0 <= r["cvss"] < 7.0),
            "low_count": sum(1 for r in results if r["cvss"] < 4.0),
            "avg_cvss": sum(r["cvss"] for r in results) / len(results) if results else 0
        },
        "vulnerabilities": results
    }
    
    return report


def save_report(report: dict[str, Any]) -> str:
    """Save report to JSON file and return the path."""
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{timestamp}.json"
    filepath = os.path.join(reports_dir, filename)
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    return filepath


def main():
    """Main dashboard application."""
    # Header
    st.markdown('<p class="main-header">🏹 MergenSec</p>', unsafe_allow_html=True)
    st.markdown("**Autonomous Vulnerability Mapping Framework**")
    st.markdown("---")
    
    # Sidebar - Scan Configuration
    st.sidebar.header("Scan Configuration")
    
    target = st.sidebar.text_input(
        "Target IP or CIDR",
        value="192.168.1.1",
        help="Enter the target IP address or CIDR range to scan"
    )
    
    port_range = st.sidebar.text_input(
        "Port Range",
        value="21, 22, 80, 443, 3306, 8080",
        help="Comma-separated list of ports to scan"
    )
    
    scan_type = st.sidebar.selectbox(
        "Scan Type",
        options=["Quick Scan", "Full Scan", "Custom"],
        index=0
    )
    
    st.sidebar.markdown("---")
    st.sidebar.header("Settings")
    
    auto_refresh = st.sidebar.checkbox(
        "Auto-refresh results",
        value=False
    )
    
    show_advanced = st.sidebar.checkbox(
        "Show advanced options",
        value=False
    )
    
    if show_advanced:
        st.sidebar.text_input("NVD API Key", type="password")
        st.sidebar.slider("Request timeout (seconds)", 10, 60, 30)
    
    # Main content area
    tab1, tab2, tab3 = st.tabs(["Dashboard", "Scan Results", "Reports"])
    
    with tab1:
        # Dashboard overview
        st.header("Security Overview")

        # Use real scan results if available, otherwise show sample data
        if "scan_results" in st.session_state and st.session_state["scan_results"]:
            dashboard_results = st.session_state["scan_results"]
            st.info(f"Showing results from last scan on target: **{st.session_state.get('scan_target', 'N/A')}**")
        else:
            dashboard_results = load_sample_data()
            st.caption("Showing sample data — run a scan in the 'Scan Results' tab to see real results.")

        # Display metrics
        display_metrics(dashboard_results)

        # Display charts
        col1, col2 = st.columns(2)

        with col1:
            display_risk_distribution(dashboard_results, key="dashboard")

        with col2:
            display_cvss_histogram(dashboard_results, key="dashboard")

        # Recent scans section
        st.markdown("---")
        st.header("Recent Scans")
        
        if os.path.exists("reports"):
            report_files = sorted(
                [f for f in os.listdir("reports") if f.endswith(".json")],
                reverse=True
            )[:5]
            
            if report_files:
                for report_file in report_files:
                    report_path = os.path.join("reports", report_file)
                    with open(report_path, "r") as f:
                        report_data = json.load(f)
                    
                    with st.expander(f"Scan: {report_data['scan_info']['target']} - {report_data['scan_info']['timestamp'][:19]}"):
                        st.write(f"**Target:** {report_data['scan_info']['target']}")
                        st.write(f"**Total Vulnerabilities:** {report_data['summary']['total_vulnerabilities']}")
                        st.write(f"**Critical:** {report_data['summary']['critical_count']}")
                        st.write(f"**High:** {report_data['summary']['high_count']}")
            else:
                st.info("No previous scans found.")
        else:
            st.info("Reports directory not found.")
    
    with tab2:
        # Scan results tab
        st.header("Vulnerability Scan Results")
        
        # Start scan button
        if st.button("Start Scan", type="primary"):
            # Parse port range
            try:
                ports = [int(p.strip()) for p in port_range.split(",")]
                
                # Progress bar
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # Simulate scan with progress
                status_text.text("Initializing scan...")
                time.sleep(0.5)
                
                results = []
                for i, port in enumerate(ports):
                    status_text.text(f"Scanning port {port}...")
                    progress_bar.progress((i + 1) / len(ports))
                    
                    vuln = map_vulnerability(port)
                    if vuln:
                        results.append(vuln)
                
                status_text.text("Scan complete!")
                time.sleep(0.5)
                status_text.empty()
                progress_bar.empty()
                
                # Store results in session state
                st.session_state["scan_results"] = results
                st.session_state["scan_target"] = target
                
                st.success(f"Scan completed! Found {len(results)} vulnerabilities.")
                
            except ValueError as e:
                st.error(f"Invalid port range: {e}")
        
        # Display scan results
        if "scan_results" in st.session_state:
            results = st.session_state["scan_results"]
            
            if results:
                st.markdown("### Scan Results")
                display_metrics(results)
                
                col1, col2 = st.columns(2)
                with col1:
                    display_risk_distribution(results, key="scan")
                with col2:
                    display_cvss_histogram(results, key="scan")
                
                display_vulnerability_table(results)
                
                # Export button
                st.markdown("---")
                report = generate_report(results, st.session_state["scan_target"])
                report_path = save_report(report)
                
                st.success(f"Report saved to: {report_path}")
                
                # Download button
                st.download_button(
                    label="Download JSON Report",
                    data=json.dumps(report, indent=2, ensure_ascii=False),
                    file_name=os.path.basename(report_path),
                    mime="application/json"
                )
            else:
                st.info("No vulnerabilities found in the scan.")
    
    with tab3:
        # Reports tab
        st.header("Generated Reports")
        
        if os.path.exists("reports"):
            report_files = sorted(
                [f for f in os.listdir("reports") if f.endswith(".json")],
                reverse=True
            )
            
            if report_files:
                for report_file in report_files:
                    report_path = os.path.join("reports", report_file)
                    with open(report_path, "r", encoding="utf-8") as f:
                        report_data = json.load(f)
                    
                    with st.expander(f"📄 {report_file}"):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write(f"**Target:** {report_data['scan_info']['target']}")
                            st.write(f"**Timestamp:** {report_data['scan_info']['timestamp']}")
                            st.write(f"**Total:** {report_data['summary']['total_vulnerabilities']}")
                        
                        with col2:
                            st.write(f"**Critical:** {report_data['summary']['critical_count']}")
                            st.write(f"**High:** {report_data['summary']['high_count']}")
                            st.write(f"**Medium:** {report_data['summary']['medium_count']}")
                            st.write(f"**Low:** {report_data['summary']['low_count']}")
                        
                        st.markdown("---")
                        
                        # Download button for each report
                        with open(report_path, "r", encoding="utf-8") as f:
                            report_content = f.read()
                        
                        st.download_button(
                            label="⬇️ Download JSON Report",
                            data=report_content,
                            file_name=report_file,
                            mime="application/json",
                            key=f"dl_{report_file}"
                        )
            else:
                st.info("No reports found. Run a scan to generate reports.")
        else:
            st.info("Reports directory not found.")
    
    # Footer
    st.markdown("---")
    st.markdown(
        """
        <div style='text-align: center; color: #666;'>
            <p>🏹 MergenSec - Autonomous Vulnerability Mapping Framework</p>
            <p>Built with Python, Streamlit, and Nmap</p>
        </div>
        """,
        unsafe_allow_html=True
    )


if __name__ == "__main__":
    main()