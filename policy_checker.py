import os
import psutil


def check_firewall():
    status = os.system("netsh advfirewall show allprofiles")
    if status == 0:
        print("Firewall is active.")
    else:
        print("Firewall is inactive.")


def check_antivirus():
    # Checking if common antivirus processes are running
    # Add more processes based on your environment
    av_processes = ['avguard.exe', 'msmpeng.exe']
    for proc in psutil.process_iter():
        if proc.name().lower() in av_processes:
            print(f"Antivirus {proc.name()} is running.")
            return
    print("No active antivirus detected.")


def check_disk_encryption():
    # Check if BitLocker (Windows) or similar encryption is enabled
    encryption_status = os.system("manage-bde -status")
    if encryption_status == 0:
        print("Disk encryption is enabled.")
    else:
        print("Disk encryption is not enabled.")


def check_admin_accounts():
    # Check for admin accounts
    admin_accounts = [user.name for user in psutil.users()
                      if 'admin' in user.name.lower()]
    if admin_accounts:
        print(f"Admin accounts found: {admin_accounts}")
    else:
        print("No admin accounts detected.")


def check_system_updates():
    # Check if system updates are enabled
    update_status = os.system("powershell Get-WindowsUpdate")
    if update_status == 0:
        print("System updates are enabled and up to date.")
    else:
        print("System updates are not enabled or pending.")


if __name__ == "__main__":
    check_firewall()
    check_antivirus()
    check_disk_encryption()
    check_admin_accounts()
    check_system_updates()
