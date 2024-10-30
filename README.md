SEIM deployment with Wazuh manager in a virtualized security enviromentSEIM deployment with Wazuh manager in a virtualized security enviroment

    Project overview:
        This project integrates the Wazuh solution in a virtual infrastructure of multiple VMs, where on of them will be running Wazuh manager and the rest of the end devices will be running Wazug agent 
        this sollution deployment aims to provides for each node these security operations:
         - Security configuration assessment (SCA)
         - Log analysis and Threat intelligence
         - Instrution and malware detection
         - File integrity monitoring
         - Vulnerabilities detection
         - assuring regulatory compliance
         - System inventory

    Infrastructure components:
         - Debian 12 VM running Wazuh manager (server, indexer and dashboard)
         - Windows Server 2022 VM running Active Directory
         - Centos 7 VM running Cloudera 
         - Centos 8 VM running Snort NIDS
         - NatNetwork integration in Virtualbox with DHCP implementation

    
    The Wazuh deployment in this infrastructure fucus mainly on Threat detection, prevention and Response capabilities by:
         - Security analysis and Infrastructure monitoring in real time
         - using CIS baselines
         - using Mitre ATT&CK framework
         - using CVE databases
         - using non-signature malware detection 
         - Implementing Automated counter mesures




















































# SIEM-deployment-with-Wazuh-in-virtualized-security-environment
Virtualized SIEM lab using Wazuh for centralized monitoring and security event management across multiple virtual Linux and Windows clients, all connected within a VirtualBox network.

Project Structure:

    Wazuh Manager and Dashboard:
        Install Wazuh manager and dashboard on an Ubuntu server VM.

    Virtual Client Machines:
        Create VMs to simulate the endpoints:
            One or more Ubuntu VMs as Linux clients.
            One or more Windows VMs as Windows clients.

    Active Directory Server:
        Install a Microsoft Windows Server VM with Active Directory, DNS, and DHCP services.

    Wazuh Agents:
        Install Wazuh agents on all the client VMs (both Ubuntu and Windows) and the AD server.

    Networking:
        Simulate the networking using virtual switches or internal networks within your virtualization software (like VMware, VirtualBox, or Hyper-V) to replicate LAN communication.
        Configure routing between the VMs to simulate internet access if necessary.

Proposed Project Name:

"Virtual Security Monitoring Lab with Wazuh and AD"

This name highlights the virtualized nature of your project and its focus on security monitoring with Wazuh and Active Directory. If you prefer a shorter name:

"Wazuh-Driven Virtual Security Lab"

This emphasizes the core tool (Wazuh) and the fact that it's a virtual lab for security monitoring.
Tools You'll Need:

    Virtualization software: VMware Workstation, VirtualBox, or Hyper-V.
    Ubuntu ISO for the Wazuh manager and Ubuntu client VMs.
    Microsoft Windows Server ISO for the AD and Windows client VMs.
    Wazuh platform for security monitoring.




****************************************
This project aims to create a virtualized Wazuh-centered network for monitoring and security event analysis. The environment was designed to include several virtual machines, with an Active Directory server and Wazuh agents, simulating a typical IT infrastructure in a virtualized form.

Components

- Wazuh Manager (Ubuntu 22.04 VM): The central point for monitoring and analyzing security events. 
- Windows Host (Windows 11): My physical machine hosting the virtualized environment and participating as a client in the virtual network.
- Kali Linux VM: A penetration testing machine used to simulate attacks and security threats within the network.
- Ubuntu VM: A client running the Wazuh agent.
- Active Directory (Windows Server 2019 VM): Provides centralized authentication, authorization, and DNS services within the network.

Network Design

- Host-Only Network (VirtualBox): A virtualized network created using VirtualBox’s Host-Only Adapter feature.
- NAT Network: Allows VMs to access the internet while maintaining isolation from the external network.

Installation:
- Wazuh Manager: Installed on Ubuntu using official installation scripts. Configured to monitor agents running on Windows and Linux clients.
- Active Directory: Installed on Windows Server 2019. Configured to provide DNS services for internal hostname resolution and user management.
- Wazuh Agents: Installed on all clients, configured to report to the Wazuh Manager.