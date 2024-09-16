import os
import psutil
import logging
import subprocess


# Configure logging
logging.basicConfig(filename="policy_checker.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")


class PolicyChecker:
    """A class for checking system security policies and configurations."""

    def __init__(self):
        self.firewall_status = None
        self.antivirus_status = None
        self.encryption_status = None
        self.admin_accounts = None

    def check_firewall(self):
        """Check the status of the system firewall."""
        status = os.system("netsh advfirewall show allprofiles")
        if status == 0:
            self.firewall_status = "Active"
        else:
            self.firewall_status = "Inactive"

    def check_antivirus(self):
        """Check if any antivirus software is running."""
        av_processes = ['avguard.exe', 'msmpeng.exe']
        active_av = False
        for proc in psutil.process_iter():
            if proc.name().lower() in av_processes:
                active_av = True
                break
        self.antivirus_status = "Active" if active_av else "Inactive"

    def check_disk_encryption(self):
        """Check if disk encryption (e.g., BitLocker) is enabled."""
        encryption_status = os.system("manage-bde -status")
        self.encryption_status = "Enabled" if encryption_status == 0 else "Disabled"

    def check_admin_accounts(self):
        """Check for the presence of administrative accounts."""
        admin_accounts = [
            user.name for user in psutil.users() if 'admin' in user.name.lower()]
        self.admin_accounts = admin_accounts if admin_accounts else "No admin accounts"

    def run_all_checks(self):
        """Run all system policy checks and return results as a dictionary."""
        self.check_firewall()
        self.check_antivirus()
        self.check_disk_encryption()
        self.check_admin_accounts()

        return {
            'Component': ['Firewall', 'Antivirus', 'Disk Encryption', 'Admin Accounts'],
            'Status': [self.firewall_status, self.antivirus_status, self.encryption_status, 'Found' if self.admin_accounts else 'None'],
            'Details': [f'Firewall is {self.firewall_status}',
                        f'Antivirus is {self.antivirus_status}',
                        f'Disk encryption is {self.encryption_status}',
                        f'Admin accounts: {self.admin_accounts if self.admin_accounts != "No admin accounts" else "None"}']
        }


if __name__ == "__main__":
    checker = PolicyChecker()
    checker.run_all_checks()
