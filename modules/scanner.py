import nmap
import ipaddress  # For IP range validation
import threading

from queue import Queue


def scan_network(target_ip, scan_type='fast'):
    nm = nmap.PortScanner()
    scan_args = {'fast': '-F', 'os': '-O', 'service': '-sV'}

    try:
        scan_result = nm.scan(
            target_ip, arguments=scan_args.get(scan_type, '-F'))
    except Exception as e:
        return {}

    # Parse results into a structured format for reporting
    results = {'Component': [], 'Status': [], 'Details': []}

    for host in scan_result.get('scan', {}):
        ipv4 = scan_result['scan'][host]['addresses'].get('ipv4', 'N/A')
        for proto in scan_result['scan'][host].all_protocols():
            for port in scan_result['scan'][host][proto].keys():
                port_info = scan_result['scan'][host][proto][port]
                state = port_info.get('state', 'unknown')
                service = port_info.get('name', 'unknown')
                results['Component'].append(f'{ipv4} - Port {port}')
                results['Status'].append(state)
                results['Details'].append(
                    f'Service: {service}, State: {state}')

    return results


def display_scan_results(scan_result):
    """
    Displays the scan results in a user-friendly format.

    Args:
        scan_result (dict): The result of the network scan.
    """
    if not scan_result or 'scan' not in scan_result:
        print("No scan results found.")
        return

    print("\n--- Scan Results ---")
    for host in scan_result['scan']:
        print(f"Host: {host}")
        ipv4 = scan_result['scan'][host]['addresses'].get('ipv4', 'N/A')
        print(f"  IPv4: {ipv4}")

        for proto in scan_result['scan'][host].all_protocols():
            print(f"  Protocol: {proto}")
            ports = scan_result['scan'][host][proto].keys()
            for port in ports:
                port_info = scan_result['scan'][host][proto][port]
                state = port_info.get('state', 'unknown')
                name = port_info.get('name', 'unknown')
                print(f"    Port: {port} -> State: {state}, Service: {name}")


def async_scan(target_ips, scan_type='fast', num_threads=4):
    """
    Performs asynchronous scanning by distributing the scan across multiple threads.

    Args:
        target_ips (list): A list of target IP addresses or ranges.
        scan_type (str): The type of scan to perform (fast, os, service).
        num_threads (int): The number of threads to use for scanning.

    """
    def worker():
        while not queue.empty():
            target_ip = queue.get()
            result = scan_network(target_ip, scan_type)
            display_scan_results(result)
            queue.task_done()

    queue = Queue()
    for ip in target_ips:
        queue.put(ip)

    for _ in range(num_threads):
        thread = threading.Thread(target=worker)
        thread.daemon = True
        thread.start()

    queue.join()  # Block until all tasks are done


def validate_ip_range(ip_range):
    """
    Validates the provided IP range.

    Args:
        ip_range (str): The IP range provided by the user.

    Returns:
        bool: True if the IP range is valid, False otherwise.
    """
    try:
        ipaddress.IPv4Network(ip_range)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    # Main program logic
    target_ip = input("Enter the target IP range (e.g., 192.168.1.0/24): ")
    if not validate_ip_range(target_ip):
        print("Invalid IP range. Please enter a valid range.")
        exit()

    scan_type = input("Choose scan type (fast, os, service): ").lower()
    if scan_type not in ['fast', 'os', 'service']:
        print("Invalid scan type. Please choose from 'fast', 'os', or 'service'.")
        exit()

    # Asynchronous scanning for multiple IP ranges (for larger network ranges)
    target_ips = [target_ip]
    async_scan(target_ips, scan_type, num_threads=4)
