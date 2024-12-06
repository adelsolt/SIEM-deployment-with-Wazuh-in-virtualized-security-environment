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
         - Debian 12 VM running Docker Containers 
            - Wazuh Manager 4.9.2 container
            - Wazuh Indexer 4.9.2 container
            - Wazuh Dashboard 4.9.2 container
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


# Wazuh Manager Configuration

First i Deployed the Debian 12 VM running the 3 Wazuh Containers
Setting up the Wazuh manager configuration that is in /var/ossec/etc/ossec.conf
The wazuh manager will collect logs from machines with the agent installed or with agentlless machines (connected with ssh) such as Network Hardware.


This bloc has mostly the default configuration for the agent connections to the manager (i will change later to enhance security posture)
```
<!-- Configuration for wazuh-authd -->
  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>no</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <!-- <ssl_agent_ca></ssl_agent_ca> -->
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>
```


# Agent connection service

This specific bloc configure service connection
```
<ossec_config>
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>
</ossec_config>
```
The agents will forward security events to the manager on port 1514
for the protocol i choose tcp for the connection to make sure that there will be no loss in the communication

# Decoding logs and Evaluating Rules

I tested a logtest provided in the documentation to see how the Wazuh Manager decodes the logs by assigning the compatible decoder (decoder are in /var/ossec/rulesets/decoders/0310-ssh_decoders.xml) to extract intelligence for analysis

Then the manager compares it against a ruleset (rules are stored in /var/ossec/ruleset/rules xml format) and if the rule is met, it evaluates an alert for that specific rule.   
Only rules above level 2 generates Alerts!

# Integrating Wazuh Indexer

This integration makes a connection between the Wazuh manager and the Wazuh indexer, where the events analysed by the manager will be tranported to the Indexer with Filebeat for storage and archive

# Wazuh Indexer Connector 

The Wazuh manager forwards Vulnerability data to the indexer connector who then forward them to the Wazuh Indexer (JSON format) 
The connector config is in the Wazuh manager config file as well 

```
<ossec_config>
 <indexer>
    <enabled>yes</enabled>
    <hosts>
      <host>https://127.0.0.1:9200</host>
    </hosts>
    <ssl>
      <certificate_authorities>
        <ca>/etc/filebeat/certs/root-ca.pem</ca>
      </certificate_authorities>
      <certificate>/etc/filebeat/certs/filebeat.pem</certificate>
      <key>/etc/filebeat/certs/filebeat-key.pem</key>
    </ssl>
  </indexer>
</ossec_config>
```

# The Alert management

 By default, the alerts are stored in 
    /var/ossec/logs/alerts/alerts.log 
     /var/ossec/logs/alerts/alerts.json 

and by default wazuh manager uses filebeat to forward alerts to wazuh indexer (we can also configure it to forward alerts to syslog servers or email systems) 

# Alerts severity 

Alerts are triggered depending on the severity level configured (ranges from 1 to 7)
I want the SEIM envirment to target most of the events so i setted the minimuim severity level to generate an alert to 2 and minimuim severity level to trigger an email to 10 (range from 1 to 16)

```
<ossec_config>
  <alerts>
    <log_alert_level>2</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>
</ossec_config>
```


# Setting up my email as alerts reciepient

Wazuh dosn't support SNTP servers authentication like gmail (which my email is from) so i will beusing a server relay by configuring POSTfix with Gmail by Appending these configurations to /etc/postfix.main.cf

```
relayhost = [smtp.gmail.com]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/ca-bundle.crt
smtp_use_tls = yes
```

Then setting up the sender credentiels in the /etc/postfix/sasl_passwd file, then securing it to be accessible only by root

```
echo [smtp.gmail.com]:587 soltane@gmail.com:TemporaryPassword > /etc/postfix/sasl_passwd
postmap /etc/postfix/sasl_passwd
chown root:root /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
chmod 0600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
```

# Events logging and storage 

To avoid events accumulation and disk overwealming i will activate the event logging archieving process that archieves events daily in 
/var/ossec/logs/archives/archives.log

```
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>yes</logall>
    <logall_json>yes</logall_json
    ......
   </global>
</ossec_config>
```













