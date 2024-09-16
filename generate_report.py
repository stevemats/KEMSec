import sys
import argparse
import logging
import time
import os
from datetime import datetime

import pandas as pd
import matplotlib.pyplot as plt
from tqdm import tqdm
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
from colorama import Fore, Style, init

from modules.scanner import scan_network, validate_ip_range
from modules.policy_checker import PolicyChecker

# Initialize colorama
init(autoreset=True)

# Setup logging
logging.basicConfig(
    filename='report_generation.log',
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Dirs
REPORT_DIR = 'reports'
IMG_DIR = os.path.join(REPORT_DIR, 'images')
HTML_TEMPLATE_DIR = 'templates'
HTML_TEMPLATE_PATH = 'report_template.html'

# Create dirs if they don't exist
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(IMG_DIR, exist_ok=True)

# Helper Functions


def setup_template_engine():
    """Sets up the Jinja2 template env for efficient rendering."""
    env = Environment(loader=FileSystemLoader(HTML_TEMPLATE_DIR))
    return env


def generate_html_report(dataframe, chart_path):
    """
    Generates an HTML report using Jinja2 rendering.
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

        # Save the HTML report
        report_file = os.path.join(REPORT_DIR, f'report_{current_time}.html')
        with open(report_file, 'w') as f:
            f.write(report)

        logging.info(f"HTML report generated successfully: {report_file}")
        return report_file

    except Exception as e:
        logging.error(f"Error generating HTML report: {e}")
        raise


def generate_pdf_report(html_report_path, pdf_output_path):
    """
    Converts an HTML report into a PDF using WeasyPrint.
    """
    try:
        logging.info(f"Converting HTML report {html_report_path} to PDF.")
        HTML(html_report_path).write_pdf(pdf_output_path)
        logging.info(f"PDF report generated successfully: {pdf_output_path}")
        return pdf_output_path
    except Exception as e:
        logging.error(f"Error generating PDF report: {e}")
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


def run_policy_checks():
    """
    Execute policy checks and return results with detailed logging.
    """
    try:
        checker = PolicyChecker()
        for _ in tqdm(range(10), desc="Running Policy Checks", ncols=100):
            time.sleep(0.2)  # progress simulation
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
        print(Fore.YELLOW + "Starting network scan...")
        scan_results = scan_network(target_ip, scan_type='fast')

        open_ports = []
        for _ in tqdm(range(100), desc="Scanning Network", ncols=100):
            time.sleep(0.03)  # network scan progress simulation

        if 'scan' in scan_results:
            for host, result in scan_results['scan'].items():
                for proto in result['all_protocols']():
                    open_ports += [f"Port {port}" for port in result[proto].keys()]

        logging.info(f"Network scan completed. Open ports: {open_ports}")
        print(Fore.GREEN + "Network scan completed!")
        return open_ports

    except Exception as e:
        logging.error(f"Error running network scan: {e}")
        raise


def display_menu():
    """KEMSec Tool options."""
    print(Fore.CYAN + "\n--- Main Menu ---")
    print(Fore.CYAN + "1. Run Network Scan")
    print(Fore.CYAN + "2. Run Policy Checks")
    print(Fore.CYAN + "3. Generate Report (HTML/PDF)")
    print(Fore.CYAN + "4. Exit")


def interactive_menu():
    """Interactive menu system for handling user choices."""
    while True:
        display_menu()
        choice = input("\nEnter your choice: ")

        if choice == "1":
            target_ip = input("Enter target IP range (e.g., 192.168.1.0/24): ")
            if validate_ip_range(target_ip):
                open_ports = run_network_scan(target_ip)
                print(f"Open Ports: {open_ports}")
            else:
                print(Fore.RED + "Invalid IP range. Try again.")

        elif choice == "2":
            policy_results = run_policy_checks()
            print(f"Policy Check Results: {policy_results}")

        elif choice == "3":
            report_type = input("Choose report format (HTML/PDF): ").lower()
            target_ip = input("Enter target IP range for scan: ")
            if validate_ip_range(target_ip):
                open_ports = run_network_scan(target_ip)
                policy_results = run_policy_checks()

                # Combine results into DataFrame
                data = {
                    'Component': ['Network Scan', 'Firewall', 'Antivirus', 'Disk Encryption'],
                    'Status': ['Open Ports Detected' if open_ports else 'No Open Ports'] + list(policy_results.values()),
                    'Details': [', '.join(open_ports) if open_ports else 'No open ports detected'] + ['N/A'] * 3
                }
                df = pd.DataFrame(data)

                chart_path = generate_status_pie_chart(df)
                if report_type == 'html':
                    generate_html_report(df, chart_path)
                elif report_type == 'pdf':
                    html_report_path = generate_html_report(df, chart_path)
                    current_time = datetime.now().strftime('%Y-%m-%d %H-%M-%S')
                    pdf_report_path = os.path.join(
                        REPORT_DIR, f'report_{current_time}.pdf')
                    generate_pdf_report(html_report_path, pdf_report_path)

        elif choice == "4":
            print(Fore.GREEN + "Exiting...")
            break

        else:
            print(Fore.RED + "Invalid choice. Please try again.")


def parse_arguments():
    """Command-line argument parsing."""
    parser = argparse.ArgumentParser(description="KEMSA Security Audit Tool")
    parser.add_argument(
        '--report', help="Generate a report (HTML/PDF)", choices=['html', 'pdf'])
    parser.add_argument('--scan', help="Run a network scan",
                        action='store_true')
    return parser.parse_args()


# Main Program Execution
if __name__ == "__main__":
    args = parse_arguments()

    if args.scan:
        target_ip = input("Enter target IP range (e.g., 192.168.1.0/24): ")
        if validate_ip_range(target_ip):
            open_ports = run_network_scan(target_ip)
            print(f"Open Ports: {open_ports}")
        else:
            print(Fore.RED + "Invalid IP range. Exiting.")
            exit()

    elif args.report:
        target_ip = input("Enter target IP range for scan: ")
        if validate_ip_range(target_ip):
            open_ports = run_network_scan(target_ip)
            policy_results = run_policy_checks()

            data = {
                'Component': ['Network Scan', 'Firewall', 'Antivirus', 'Disk Encryption'],
                'Status': ['Open Ports Detected' if open_ports else 'No Open Ports'] + list(policy_results.values()),
                'Details': [', '.join(open_ports) if open_ports else 'No open ports detected'] + ['N/A'] * 3
            }
            df = pd.DataFrame(data)

            chart_path = generate_status_pie_chart(df)
            if args.report == 'html':
                generate_html_report(df, chart_path)
            elif args.report == 'pdf':
                html_report_path = generate_html_report(df, chart_path)
                current_time = datetime.now().strftime('%Y-%m-%d %H-%M-%S')
                pdf_report_path = os.path.join(
                    REPORT_DIR, f'report_{current_time}.pdf')
                generate_pdf_report(html_report_path, pdf_report_path)

    else:
        interactive_menu()
