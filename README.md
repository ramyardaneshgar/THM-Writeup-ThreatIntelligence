# THM-Writeup-ThreatIntelligence
Writeup for TryHackMe Threat Intelligence - IOC-based threat intelligence in SOC operations using Kibana, ElastAlert, Sigma, and DNS sinkholing. 

By Ramyar Daneshgar 

## **Task 1: Threat Intelligence Feeds**
#### Steps Taken:
1. **Understand Types of Threat Intelligence**:
   - Focused on Technical Intelligence, as it provides direct artifacts (IPs, hashes, domains, URLs) for detection and prevention.

2. **Differentiate Producers and Consumers**:
   - Producers gather and share intelligence (e.g., from honeypots or network telemetry).
   - Consumers utilize intelligence to secure assets, identify vulnerabilities, and respond to incidents.

3. **Consume IOC Feeds**:
   - Queried logs from a simulated ELK stack using **KQL** in **Kibana** to detect IOC hits.
   - Processed IOCs (IPs) to identify matches within logs.

#### Tools, Commands, and Configurations:
- **Kibana (Part of ELK Stack)**:
  - **Login**: Accessed via `http://<Machine_IP>` using credentials `elastic:elastic`.
  - Queried IOCs using **KQL** in the `Discover` tab.
    Example Query:
    ```kql
    destination.ip: ("117.213.7.8" OR "119.180.220.224" OR "144.202.127.44")
    ```
  - Specified index: `filebeat-*`.
  - Defined the time range: `02/14/2023` to `02/17/2023`.

#### Why It’s Important:
This step demonstrates how to operationalize IOCs within a SIEM. Analysts must master querying techniques (KQL) to correlate IOCs with activity logs quickly and accurately.

---

## **Task 2: Intelligence-Driven Prevention**
#### Steps Taken:
1. **IP Blocking via Firewalls**:
   - Added malicious IPs to blocklists to deny inbound/outbound connections.

2. **Domain Blocking via Email Gateways**:
   - Configured rules to filter incoming emails from malicious domains to prevent phishing.

3. **DNS Sinkholing**:
   - Configured DNS to redirect requests for malicious domains to a designated sinkhole IP (e.g., `192.168.5.13`).
   - Verified sinkholed domains in logs.

#### Tools, Commands, and Configurations:
- **IP Blocking via Firewall**:
  - Added rules to drop traffic to/from malicious IPs:
    ```bash
    iptables -A INPUT -s 117.213.7.8 -j DROP
    iptables -A OUTPUT -d 117.213.7.8 -j DROP
    iptables-save > /etc/iptables/rules.v4
    ```
  - Verified rules:
    ```bash
    iptables -L -v
    ```

- **Domain Blocking via Email Gateways**:
  - Populated blocklists in the email gateway:
    ```plaintext
    blocked_domains.txt:
    agrosaoxe.info
    malspamdomain.com
    ```
  - Applied the blocklist in Postfix or similar:
    ```bash
    postmap hash:/etc/postfix/blocked_domains
    systemctl restart postfix
    ```

- **DNS Sinkhole**:
  - Configured `/etc/hosts` to redirect DNS queries:
    ```bash
    echo "192.168.5.13 agrosaoxe.info" >> /etc/hosts
    ```
  - Queried logs in Kibana:
    ```kql
    dns.question.name: "agrosaoxe.info"
    dns.answers.data: "192.168.5.13"
    ```

#### Why It’s Important:
Proactively blocking malicious activity at multiple layers (network, email, DNS) minimizes the risk of compromise and reduces attack surfaces.

---

## **Task 3: Intelligence-Driven Detection**
#### Steps Taken:
1. **Use Sigma Rules**:
   - Converted Sigma rules to ElastAlert-compatible YAML for automated detection.

2. **Run Detection Queries in Kibana**:
   - Queried DNS logs to detect connections to sinkholed domains.

3. **Analyze Alerts**:
   - Used **ElastAlert** to generate alerts for IOC matches.
   - Reviewed alert logs for unique sinkholed domains and suspicious activity.

#### Tools, Commands, and Configurations:
- **Sigma Rule Conversion**:
  - Accessed **Uncoder.io** to translate Sigma rules into ElastAlert YAML:
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
  - Navigated to ElastAlert’s directory:
    ```bash
    cd ~/elastalert/rules
    ```
  - Verified ElastAlert configuration:
    ```bash
    elastalert-test-rule --config config.yaml sinkhole.yaml
    ```
  - Ran ElastAlert to generate alerts:
    ```bash
    elastalert --start 2023-02-16T00:00:00 --verbose 2>&1 | tee output.txt
    ```

- **Query in Kibana**:
  - Detected sinkholed domains:
    ```kql
    dns.answers.data: "0.0.0.0"
    ```

#### Why It’s Important:
Detection bridges the gap between prevention and response. Automating alerts with ElastAlert ensures real-time visibility into malicious activity, enabling rapid incident response.

---

## **Task 4: Conclusion**
#### Steps Taken:
1. **Summarized Learnings**:
   - Reinforced the importance of producers and consumers in the threat intelligence ecosystem.
   - Reviewed prevention and detection strategies.

2. **Highlighted Continuous Improvement**:
   - Emphasized the need for updating IOC lists, refining Sigma rules, and evolving detection capabilities.

#### Tools and Commands:
- **Log Analysis**:
  - Reviewed ElastAlert logs:
    ```bash
    cat output.txt
    ```

#### Why It’s Important:
The conclusion reinforces the iterative nature of threat intelligence. SOC workflows must evolve to counter adversaries who continually refine their tactics.

---

### Lessons Learned

1. **Importance of Layered Security**: Integrating prevention, detection, and response measures reinforces a defense-in-depth approach, reducing vulnerabilities and increasing overall resilience against threats.

2. **Tools**: Practical experience with tools like Kibana, ElastAlert, and Sigma equips SOC analysts to efficiently manage real-world security incidents and implement intelligence-driven operations.

3. **Value of Scalable Automation**: Automating detection and alerting workflows with ElastAlert and Sigma rules enhances efficiency, ensuring adaptability to growing threat landscapes and reducing manual intervention.

4. **Significance of Proactive Defense**: Actively addressing both known and emerging threats minimizes exposure to adversarial activities and strengthens an organization’s security posture.

