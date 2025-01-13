# **THM Writeup - Threat Intelligence**

This document outlines the precise implementation of IOC-based threat intelligence for SOC operations, focusing on the use of tools like Kibana, ElastAlert, Sigma, and DNS sinkholing. The writeup emphasizes technical configurations, queries, and workflows for improved threat detection, prevention, and response.

**By Ramyar Daneshgar**

---

### IOC-Based Threat Intelligence Ingestion

The initial step involved ingesting IOCs into the ELK stack, specifically leveraging Kibana for log analysis. By querying the `filebeat-*` index with known malicious indicators such as `117.213.7.8` and `119.180.220.224`, the SOC team correlated network activity with identified threats. Using KQL, queries like the following were executed to detect potential compromises:

```kql
destination.ip: ("117.213.7.8" OR "119.180.220.224")
```

The scope of the search was limited to a specific timeframe, between February 14 and February 17, 2023, ensuring precise event analysis. This process provided real-time visibility into malicious activity and enabled the identification of potential compromise points.

---

### Firewall-Based IP Blocking

To prevent adversarial communication, firewall rules were applied to block malicious IPs. Using iptables, the following rules were configured:

```bash
iptables -A INPUT -s 117.213.7.8 -j DROP
iptables -A OUTPUT -d 117.213.7.8 -j DROP
iptables-save > /etc/iptables/rules.v4
```

The rules ensured that traffic to and from the specified IPs was denied at the network level. Verification was conducted with:

```bash
iptables -L -v
```

By blocking ingress and egress traffic from malicious sources, this measure limited the attacker’s ability to establish or maintain communication within the network.

---

### DNS Sinkholing

DNS sinkholing was implemented to disrupt command-and-control (C2) communications. Malicious domains, such as `agrosaoxe.info`, were redirected to a controlled sinkhole IP (`192.168.5.13`). This was achieved by appending entries to the `/etc/hosts` file:

```bash
echo "192.168.5.13 agrosaoxe.info" >> /etc/hosts
```

Kibana was used to validate the sinkhole's effectiveness, querying for redirected traffic:

```kql
dns.question.name: "agrosaoxe.info" AND dns.answers.data: "192.168.5.13"
```

This approach effectively neutralized adversary communication channels, halting malware operations that relied on external infrastructure.

---

### Email Filtering

To mitigate phishing and spam attacks, malicious domains were blocklisted in the organization’s email gateway. The blocklist was configured using Postfix:

```plaintext
blocked_domains.txt:
agrosaoxe.info
malspamdomain.com
```

The list was applied with the following commands:

```bash
postmap hash:/etc/postfix/blocked_domains
systemctl restart postfix
```

This filtering process significantly reduced the risk of email-based attacks, particularly those leveraging social engineering techniques.

---

### Sigma Rule Integration and ElastAlert

Automated detection workflows were implemented by converting Sigma rules into ElastAlert-compatible YAML configurations. For example:

```yaml
alert:
  - debug
description: "Detect Sinkholed Domains"
index: filebeat-*
filter:
  - query_string:
      query: dns.resolved_ip: "0.0.0.0"
```

The rule was saved as `sinkhole.yaml` and executed with ElastAlert:

```bash
elastalert --start 2023-02-16T00:00:00 --verbose 2>&1 | tee output.txt
```

ElastAlert monitored logs for real-time matches and generated actionable alerts. The output was stored in `output.txt` for further analysis. This automated approach ensured rapid detection and response to suspicious activity.

---

### Verification and Continuous Improvement

The SOC team used Kibana queries to confirm the efficacy of implemented measures. For sinkholed domains, queries like the following validated traffic redirection:

```kql
dns.answers.data: "0.0.0.0"
```

Regular updates to IOC lists and Sigma rules were emphasized to maintain the relevance of detection mechanisms. Continuous tuning and validation ensured the SOC remained adaptive to evolving threats.

---

### Lessons Learned

- **Layered Security**: Integrating firewall rules, DNS sinkholing, email filtering, and detection workflows provided a robust defense-in-depth approach.
- **Tool Proficiency**: Mastery of Kibana, ElastAlert, and Sigma enhanced the SOC team’s ability to handle large-scale threats efficiently.
- **Automation and Scalability**: Automating detection workflows with ElastAlert reduced response times and improved scalability for managing large datasets.
- **Proactive Threat Mitigation**: Addressing known and emerging IOCs minimized the impact of adversarial actions and bolstered the organization’s overall security posture.
