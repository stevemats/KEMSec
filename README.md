# KEMSec

![KEMSec Cybersecurity Audit Tool](https://ciiblog.in/wp-content/uploads/2024/03/Cyber-Security-in-the-Industry-1024x280.png)

Infosec audit tool designed to provide comprehensive system vulnerability assessments, ensuring that e.g., healthcare institutions are protected against emerging security threats. For a start, KEMSec will focus on network security, system policy compliance, and generating detailed audit reports to help organizations improve their defenses.

## Report Overview

![KEMSec report overview](https://github.com/user-attachments/assets/a1cc014f-171b-4759-acda-14aa93f0b4fd)

## Installation

1. Download the tool:

   ```bash
   git clone https://github.com/stevemats/KEMSec.git
   ```

2. Change current working directory to the tool's folder:

   ```bash
   cd KEMSec
   ```

3. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

- Additionally you can install [Npcap](https://npcap.com/#download) to resolve any errors during scanning if you're on windows, and on linux distros use:

  ```bash
  sudo apt-get install libpcap-dev
  ```

## Usage

- Now to start the audit, all you have to do is run the below command:

  ```bash
  python generate_report.py
  ```

---

## Contribution

- You can contribute to this project in either of the following ways:

  1.  Open an issue addressing a problem, question or a feature - [Issues](https://github.com/stevemats/KEMSec/issues)

  2.  Open a Pull request to add a feature or project improvement referencing an issue. - [Pull Request](https://github.com/stevemats/KEMSec/pulls)

---
