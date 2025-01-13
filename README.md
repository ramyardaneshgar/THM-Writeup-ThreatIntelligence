# **THM-Writeup-ThreatIntelligence**

This writeup details the practical implementation of IOC-based threat intelligence for Security Operations Center (SOC) operations, leveraging tools like Kibana, ElastAlert, Sigma, and DNS sinkholing. These techniques aim to enhance threat detection, prevention, and response capabilities.

By **Ramyar Daneshgar**

---

## **Task 1: Threat Intelligence Feeds**

### **Steps Taken**

1. **Understand Types of Threat Intelligence**:
   - Focused on **Technical Intelligence**, which involves the use of adversarial artifacts (e.g., IP addresses, hashes, domains, URLs) to detect and prevent attacks.
   - This intelligence can be directly applied to defend against active threats, by analyzing these indicators to identify malicious activity in the network.

2. **Differentiate Producers and Consumers**:
   - **Producers**: Organizations or systems that gather and analyze threat intelligence from sources like honeypots, network traffic analysis, and incident reports.
   - **Consumers**: Organizations that use the intelligence provided by producers to enhance their security posture. This includes applying IOCs to detection systems, patching vulnerabilities, and responding to incidents.

3. **Consume IOC Feeds**:
   - Queried IOC feeds through **KQL (Kibana Query Language)** to identify whether specific IP addresses had been involved in any malicious activity within the organization’s logs.
   - This action involves searching through logs in the **ELK stack (Elasticsearch, Logstash, Kibana)** to identify matches between IOCs and events.

### **Tools, Commands, and Configurations**

- **Kibana (Part of ELK Stack)**:
  - Logged into Kibana at `http://<Machine_IP>` using the provided credentials: `elastic:elastic`.
  - Used **KQL** to query the `filebeat-*` index for known malicious IPs:
    ```kql
    destination.ip: ("117.213.7.8" OR "119.180.220.224" OR "144.202.127.44")
    ```
  - Defined a time range of `02/14/2023` to `02/17/2023` to focus on relevant events.

### **Technical Impact**

- **Enhanced Threat Visibility**: Using Kibana’s querying capabilities, we mapped IOCs to system events, giving SOC teams a comprehensive view of ongoing malicious activity.
- **Operationalizing Threat Intelligence**: By distinguishing between producers and consumers, we set a clear framework for how threat intelligence should flow through SOC operations, ensuring it is actionable.
- **Efficient Detection Coverage**: With KQL and Kibana, we ensured that IOC-based indicators were properly correlated with log data, enhancing threat visibility across the network.

---

## **Task 2: Intelligence-Driven Prevention**

### **Steps Taken**

1. **IP Blocking via Firewalls**:
   - Added malicious IPs to a blocklist and configured firewalls to deny inbound and outbound traffic from these addresses.
   - This measure prevents attackers from accessing or exfiltrating data through compromised IPs.

2. **Domain Blocking via Email Gateways**:
   - Configured email filters to block incoming communications from known malicious domains.
   - This effectively reduces the risk of phishing and malware delivered via email.

3. **DNS Sinkholing**:
   - Redirected DNS queries for known malicious domains to a "sinkhole" IP (e.g., `192.168.5.13`), disrupting adversarial C2 communications and preventing further exploitation.

### **Tools, Commands, and Configurations**

- **IP Blocking via Firewall**:
  - Added firewall rules to block specific IPs:
    ```bash
    iptables -A INPUT -s 117.213.7.8 -j DROP
    iptables -A OUTPUT -d 117.213.7.8 -j DROP
    iptables-save > /etc/iptables/rules.v4
    ```
  - Verified the rules:
    ```bash
    iptables -L -v
    ```

- **Domain Blocking via Email Gateway**:
  - Populated blocklists to filter email traffic:
    ```plaintext
    blocked_domains.txt:
    agrosaoxe.info
    malspamdomain.com
    ```
  - Applied blocklist via Postfix:
    ```bash
    postmap hash:/etc/postfix/blocked_domains
    systemctl restart postfix
    ```

- **DNS Sinkholing**:
  - Edited the `/etc/hosts` file to redirect malicious queries:
    ```bash
    echo "192.168.5.13 agrosaoxe.info" >> /etc/hosts
    ```
  - Queried DNS logs to verify the sinkholing:
    ```kql
    dns.question.name: "agrosaoxe.info"
    dns.answers.data: "192.168.5.13"
    ```

### **Technical Impact**

- **Proactive Threat Mitigation**: The firewall rules blocked ingress and egress traffic from known malicious IPs, limiting exposure to exploit attempts.
- **Reduced Email-Based Attack Surface**: Filtering malicious domains at the email gateway minimized the risk of phishing attacks and malware delivery via email.
- **Disrupted Adversary Command-and-Control**: DNS sinkholing prevented adversaries from reaching their infrastructure, significantly disrupting their ability to execute attacks.

---

## **Task 3: Intelligence-Driven Detection**

### **Steps Taken**

1. **Use Sigma Rules**:
   - Converted Sigma detection rules into **ElastAlert**-compatible YAML configuration to automate detection of malicious activity.
   - These rules help identify traffic to sinkholed domains, a strong indicator of compromised systems.

2. **Run Detection Queries in Kibana**:
   - Queried DNS logs for connections to sinkholed domains to detect active infections or compromised hosts.

3. **Analyze Alerts**:
   - Used **ElastAlert** to generate automated alerts based on matching IOCs (like IP addresses or DNS queries) in real-time.
   - Analyzed the alerts for patterns of suspicious activity that require further investigation.

### **Tools, Commands, and Configurations**

- **Sigma Rule Conversion**:
  - Translated Sigma rules into ElastAlert YAML using **Uncoder.io**:
    ```yaml
    alert:
      - debug
    description: "DNS Sinkhole Detection"
    index: filebeat-*
    filter:
      - query_string:
          query: dns.resolved_ip: "0.0.0.0"
    ```
  - Saved the rule as `sinkhole.yaml`.

- **ElastAlert Configuration**:
  - Navigated to the ElastAlert directory and verified the rule configuration:
    ```bash
    cd ~/elastalert/rules
    elastalert-test-rule --config config.yaml sinkhole.yaml
    ```
  - Ran ElastAlert to start monitoring for IOC matches:
    ```bash
    elastalert --start 2023-02-16T00:00:00 --verbose 2>&1 | tee output.txt
    ```

- **Kibana Query**:
  - Queried for DNS sinkhole indicators:
    ```kql
    dns.answers.data: "0.0.0.0"
    ```

### **Technical Impact**

- **Automated Detection**: By translating Sigma rules into ElastAlert, detection capabilities were automated, reducing response time to potential threats.
- **Improved Threat Correlation**: Real-time detection of sinkholed domains allowed for faster identification of infected systems and malicious traffic patterns.
- **Enhanced SOC Response**: ElastAlert enabled the SOC to generate actionable alerts, streamlining incident response workflows and reducing the time it takes to address identified threats.

---

## **Task 4: Conclusion**

### **Steps Taken**

1. **Summarized Learnings**:
   - Reinforced the critical roles of threat intelligence producers and consumers in enhancing an organization’s security posture.
   - Reviewed detection and prevention techniques and their practical applications.

2. **Highlighted Continuous Improvement**:
   - Emphasized the need for SOC teams to continuously update IOC lists, refine Sigma rules, and evolve detection mechanisms to stay ahead of adversaries.

### **Tools and Commands**

- **Log Analysis**:
  - Reviewed ElastAlert output to identify suspicious domains:
    ```bash
    cat output.txt
    ```

### **Technical Impact**

- **Adaptive Security Posture**: Regularly updating detection rules and IOC feeds ensures SOC defenses stay relevant against emerging threats.
- **Operational Efficiency**: By automating the detection process, SOC teams can reduce manual labor and focus on high-priority incidents.
- **Collaborative Threat Intelligence**: Understanding the roles of both producers and consumers allows for effective collaboration across the cybersecurity ecosystem, strengthening overall defense mechanisms.

---

### **Lessons Learned**

1. **Defense-in-Depth Strategy**:
   - Combining prevention, detection, and response measures creates a robust multi-layered security posture, minimizing exposure to potential threats.

2. **Tools**:
   - Mastery of tools like Kibana, ElastAlert, and Sigma is essential for SOC analysts to efficiently manage real-world threat intelligence and automate detection processes.

3. **Scalable Automation**:
   - Automating detection and alerting workflows with ElastAlert and Sigma rules enhances scalability, allowing the SOC to handle increased data and threat volume without additional resources.

4. **Proactive Threat Management**:
   - By addressing both known IOCs and emerging adversarial tactics, organizations can preemptively disrupt attack attempts.
