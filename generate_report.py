import pandas as pd
from jinja2 import Template
import matplotlib.pyplot as plt
from datetime import datetime
import os

# Dummy data for the report to make sure everythings is working well
# We will replace with real data from scanner and policy_checker later
data = {
    'Component': ['Network Scan', 'Firewall', 'Antivirus'],
    'Status': ['Open Ports Detected', 'Active', 'Inactive'],
    'Details': ['Ports 80, 443 open', 'Enabled on all profiles', 'No antivirus detected']
}
df = pd.DataFrame(data)

# Report directory paths
REPORT_DIR = 'reports'
IMG_DIR = os.path.join(REPORT_DIR, 'images')
HTML_TEMPLATE_PATH = 'report_template.html'

# Create necessary directories if they don't exist
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(IMG_DIR, exist_ok=True)


def generate_html_report(dataframe, chart_path):
    """
    Generates an HTML report using the provided DataFrame and the pie chart image.
    """
    try:
        with open(HTML_TEMPLATE_PATH, 'r') as file:
            template = Template(file.read())

        # Adding metadata like timestamp and summary
        current_time = datetime.now().strftime(
            '%Y-%m-%d %H-%M-%S')  # Replace ':' with '-'
        total_components = len(dataframe)
        inactive_components = len(dataframe[dataframe['Status'] == 'Inactive'])
        open_ports = dataframe[dataframe['Status'] == 'Open Ports Detected']

        report = template.render(
            table=dataframe.to_html(
                index=False, classes='table table-striped', border=0),
            chart_path=chart_path,
            report_time=current_time,
            total_components=total_components,
            inactive_components=inactive_components,
            open_ports=open_ports
        )

        # Save report as HTML
        report_file = os.path.join(REPORT_DIR, f'report_{current_time}.html')
        with open(report_file, 'w') as f:
            f.write(report)

        print(f"Report successfully generated: {report_file}")

    except Exception as e:
        print(f"Error generating report: {e}")


def generate_status_pie_chart(df):
    """
    Generates a pie chart visualizing the security component status.
    """
    try:
        status_counts = df['Status'].value_counts()
        labels = status_counts.index
        sizes = status_counts.values

        plt.figure(figsize=(6, 6))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%',
                startangle=140, colors=['green', 'red', 'yellow'])
        plt.axis('equal')
        plt.title('System Security Status Overview')

        chart_path = os.path.join(IMG_DIR, 'status_chart.png')
        plt.savefig(chart_path)
        plt.close()

        print(f"Pie chart generated: {chart_path}")
        return chart_path

    except Exception as e:
        print(f"Error generating pie chart: {e}")
        return None


def generate_summary(df):
    """
    Generates a summary of the system's security status.
    """
    open_ports_count = len(df[df['Status'] == 'Open Ports Detected'])
    active_components = len(df[df['Status'] == 'Active'])
    inactive_components = len(df[df['Status'] == 'Inactive'])

    print("\n--- System Security Summary ---")
    print(f"Total components scanned: {len(df)}")
    print(f"Open ports detected: {open_ports_count}")
    print(f"Active components: {active_components}")
    print(f"Inactive components: {inactive_components}")
    print("\n--------------------------------")


if __name__ == "__main__":
    # Generate the pie chart
    chart_path = generate_status_pie_chart(df)

    # Generate the summary in the terminal
    generate_summary(df)

    # Generate the HTML report
    generate_html_report(df, chart_path)
