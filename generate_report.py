import pandas as pd
from jinja2 import Template, Environment, FileSystemLoader
import matplotlib.pyplot as plt
from datetime import datetime
import os
import logging
from scanner import scan_network, validate_ip_range
from policy_checker import PolicyChecker

# Setup logging
logging.basicConfig(
    filename='report_generation.log',
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Directories
REPORT_DIR = 'reports'
IMG_DIR = os.path.join(REPORT_DIR, 'images')
HTML_TEMPLATE_DIR = 'templates'
HTML_TEMPLATE_PATH = 'report_template.html'

# Create directories if they don't exist
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(IMG_DIR, exist_ok=True)

# Helper Functions


def setup_template_engine():
    """Sets up the Jinja2 template environment for efficient rendering."""
    env = Environment(loader=FileSystemLoader(HTML_TEMPLATE_DIR))
    return env


def generate_html_report(dataframe, chart_path):
    """
    Generates a professional HTML report using advanced Jinja2 rendering.
    """
    try:
        logging.info("Starting HTML report generation.")
        env = setup_template_engine()
        template = env.get_template(HTML_TEMPLATE_PATH)

        # Metadata
        current_time = datetime.now().strftime('%Y-%m-%d %H-%M-%S')
        total_components = len(dataframe)
        inactive_components = len(dataframe[dataframe['Status'] == 'Inactive'])
        open_ports = dataframe[dataframe['Status'] == 'Open Ports Detected']

        # Render HTML
        report = template.render(
            table=dataframe.to_html(
                index=False, classes='table table-striped', border=0),
            chart_path=chart_path,
            report_time=current_time,
            total_components=total_components,
            inactive_components=inactive_components,
            open_ports=open_ports,
            company_name="KEMSA Security Audit"
        )

        # Save the report
        report_file = os.path.join(REPORT_DIR, f'report_{current_time}.html')
        with open(report_file, 'w') as f:
            f.write(report)

        logging.info(f"Report generated successfully: {report_file}")
        return report_file

    except Exception as e:
        logging.error(f"Error generating HTML report: {e}")
        raise


def generate_status_pie_chart(df):
    """
    Generates a pie chart with advanced metrics and severity-based color-coding.
    """
    try:
        logging.info("Generating status pie chart.")
        status_counts = df['Status'].value_counts()
        labels = status_counts.index
        sizes = status_counts.values

        # Color code by severity
        color_map = {'Active': 'green', 'Inactive': 'red',
                     'Open Ports Detected': 'orange'}
        colors = [color_map.get(label, 'blue') for label in labels]

        plt.figure(figsize=(6, 6))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%',
                startangle=140, colors=colors)
        plt.axis('equal')
        plt.title('System Security Status Overview')

        chart_path = os.path.join(IMG_DIR, 'status_chart.png')
        plt.savefig(chart_path)
        plt.close()

        logging.info(f"Pie chart generated successfully: {chart_path}")
        return chart_path

    except Exception as e:
        logging.error(f"Error generating pie chart: {e}")
        raise


def generate_summary(df):
    """
    Produces a concise security summary of system status.
    """
    try:
        open_ports_count = len(df[df['Status'] == 'Open Ports Detected'])
        active_components = len(df[df['Status'] == 'Active'])
        inactive_components = len(df[df['Status'] == 'Inactive'])

        summary = (f"\n--- System Security Summary ---\n"
                   f"Total components scanned: {len(df)}\n"
                   f"Open ports detected: {open_ports_count}\n"
                   f"Active components: {active_components}\n"
                   f"Inactive components: {inactive_components}\n"
                   f"--------------------------------")

        logging.info("Security Summary Generated:\n" + summary)
        return summary

    except Exception as e:
        logging.error(f"Error generating security summary: {e}")
        raise


def run_policy_checks():
    """
    Execute policy checks and return results with detailed logging.
    """
    try:
        checker = PolicyChecker()
        checker.run_all_checks()

        results = {
            'Firewall': 'Active' if checker.firewall_status else 'Inactive',
            'Antivirus': 'Active' if checker.antivirus_status else 'Inactive',
            'Disk Encryption': 'Enabled' if checker.encryption_status else 'Disabled'
        }
        logging.info("Policy checks completed successfully.")
        return results

    except Exception as e:
        logging.error(f"Error in policy checks: {e}")
        raise


def run_network_scan(target_ip):
    """
    Run a network scan and return open ports with real-time logging.
    """
    try:
        logging.info(f"Running network scan on target IP range: {target_ip}")
        scan_results = scan_network(target_ip, scan_type='fast')
        open_ports = []

        if 'scan' in scan_results:
            for host, result in scan_results['scan'].items():
                for proto in result['all_protocols']():
                    open_ports += [f"Port {port}" for port in result[proto].keys()]

        logging.info(f"Network scan completed. Open ports: {open_ports}")
        return open_ports

    except Exception as e:
        logging.error(f"Error running network scan: {e}")
        raise


# Main Program Execution
if __name__ == "__main__":
    try:
        target_ip = input("Enter target IP range (e.g., 192.168.1.0/24): ")
        if not validate_ip_range(target_ip):
            logging.error("Invalid IP range provided.")
            print("Invalid IP range. Exiting.")
            exit()

        open_ports = run_network_scan(target_ip)
        policy_results = run_policy_checks()

        # Combine results into DataFrame
        data = {
            'Component': ['Network Scan', 'Firewall', 'Antivirus', 'Disk Encryption'],
            'Status': ['Open Ports Detected' if open_ports else 'No Open Ports'] + list(policy_results.values()),
            'Details': [', '.join(open_ports) if open_ports else 'No open ports detected'] + ['N/A'] * 3
        }
        df = pd.DataFrame(data)

        # Generate the pie chart
        chart_path = generate_status_pie_chart(df)

        # Generate and log the summary
        summary = generate_summary(df)
        print(summary)

        # Generate the HTML report
        generate_html_report(df, chart_path)

    except Exception as main_e:
        logging.critical(f"Critical error during main execution: {main_e}")
        raise
