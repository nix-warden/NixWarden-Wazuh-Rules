# PHP2Shell Enterprise Detection Ruleset (CVE-2026-109618 & CVE-2026-109619) 🛡️

**NixWarden Golden Ruleset** for detecting, correlating, and hunting exploitation of the critical PHP runtime memory corruption vulnerabilities (**PHP2Shell**) using the **Wazuh SIEM/XDR** platform.

> [!NOTE]
> **Source Attribution:** Based on foundational research and baseline detection logic published by Wazuh:  
> [Detecting PHP2Shell remote code execution with Wazuh](https://wazuh.com/blog/detecting-php2shell-remote-code-execution-with-wazuh/).  
> Extended and hardened by **NixWarden** into a multi-vector, cross-platform enterprise ruleset.

---

## 🔍 Vulnerability Overview

**PHP2Shell** comprises two critical engine-level memory flaws in core PHP (**CVSS v4.0: 9.2**):

* **CVE-2026-109618:** Out-of-memory (OOM) error handling flaw via `longjmp()`. Triggered when memory allocation fails during multipart request body parsing before request memory is fully initialized, causing cleanup routines to process uninitialized structures and yielding unauthenticated Remote Code Execution (RCE).
* **CVE-2026-109619:** Stale global state vulnerability where fatal errors or OOM events leave dangling pointers to freed request memory (in session upload progress and backtraces), which are reused by subsequent requests in persistent worker processes.

Because exploitation occurs inside the PHP interpreter before application frameworks (WordPress, Laravel, Drupal) execute, application-level WAF rules are easily bypassed. Detection requires multi-layered telemetry across web servers, runtime engines, and the host OS.

---

## 🏗️ Multi-Vector Architecture & Native Wazuh Hierarchy

NixWarden bridges all major web server stacks natively through Wazuh's built-in rule hierarchy (`0265-php_rules.xml`), eliminating server-specific lock-in:

```
[Nginx Error Log] -> 31301 (0260-nginx_rules.xml) --+
                                                    |---> 31402 --+
[Apache Error Log]-> 30101 (0250-apache_rules.xml) -+             |
                                                                  v
[PHP-FPM Direct]  -> 31405 (0265-php_rules.xml) ------------> 31420 (PHP Fatal error)
                                                                  |
                                                                  v
                                              NixWarden Detection Rules:
                                              - 100200: Delivery (OOM)
                                              - 100201: Delivery (Timeout)
                                              - 100204: Probing / Recon (3 in 60s)
                                              - 100202: Active Exploit (5 in 120s)
                                              - 100206 / 100207: Installation (Webshell FIM)
                                              - 100209 / 100210: C2 (Reverse Shell / Tools)
                                              - 100203 / 100208: Actions on Objectives (Exec)
```

### Telemetry Vectors & Kill Chain Progression:
1. **Phase 1: Delivery (Web Error & Access Logs):** Catches single OOM (`100200`), timeout (`100201`), and HTTP 500/502/503/504 backend crashes (`100205`) via parent `31420` / `31120`. Triage level (Level 5).
2. **Phase 2: Reconnaissance & Probing:** Correlates repeated delivery anomalies (3 events in 60s from same IP) into early warning probing alert (`100204`, Level 8).
3. **Phase 3: Exploitation (Memory Corruption):** Correlates high-frequency heap exhaustion (5 OOM events in 120s, `100202`, Level 12) or PHP-FPM worker segmentation faults / aborts (`100213`, Level 10) confirming active memory corruption (CVE-2026-109618 / CVE-2026-109619).
4. **Phase 4: Installation (File Integrity Monitoring):** Standalone web shell detection (`100206`, Level 10), escalating to Level 14 (`100207`) if preceded by active exploitation.
5. **Phase 5: Command and Control (Host Audit & Web Access):** 
   - *Host Telemetry:* Outbound reverse shell / network utility execution under web user (`100209`, Level 12), escalating to Level 14 (`100210`).
   - *Web Telemetry:* Direct HTTP 200 interaction with PHP scripts in upload/static directories (`100211`, Level 11), escalating to Level 14 (`100212`) if preceded by exploit or file drop.
6. **Phase 6: Actions on Objectives (Host Audit Telemetry):** Standalone command execution under web user (`100203`, Level 10), escalating to Level 14 (`100208`) if preceded by exploit, webshell drop, or C2 channel.

---

## 📋 Rule Catalog

All rules are assigned to the **NixWarden Web Application Security namespace (`100,200 - 100,250`)**:

| Rule ID | Level | Vector / Stage | Description | Cyber Kill Chain | MITRE ATT&CK |
|---|---|---|---|---|---|
| `100200` | 5 | Error Log / Delivery | Single PHP memory exhaustion fatal error (`Allowed memory size...`) | `kill_chain_delivery` | T1190<br>T1499.003 |
| `100201` | 5 | Error Log / Delivery | Single PHP execution timeout fatal error (`Maximum execution time...`) | `kill_chain_delivery` | T1190 |
| `100205` | 5 | Access Log / Delivery | FastCGI gateway death or timeout (502/504) on any endpoint | `kill_chain_delivery` | T1190 |
| `100214` | 5 | Access Log / Delivery | Web server 500/503 crash on PHP or API upload endpoint | `kill_chain_delivery` | T1190 |
| `100204` | 8 | Error Log / Reconnaissance | Repeated delivery anomalies (3 events in 60s from same IP) | `kill_chain_reconnaissance` | T1595.002<br>T1190 |
| `100202` | 12 | Error Log / Exploitation | High-frequency memory exhaustion (5 events in 120s). Active RCE exploit attempt. | `kill_chain_exploitation` | T1190<br>T1499.003 |
| `100213` | 10 | Error / Syslog / Exploitation | PHP-FPM worker segfault/abort or kernel segfault crash (CVE-2026-109619) | `kill_chain_exploitation` | T1190<br>T1499.003 |
| `100206` | 10 | FIM / Installation | Suspicious executable script created or modified in web/container directory | `kill_chain_installation` | T1505.003 |
| `100207` | 14 | FIM / Chained Escalation | Web shell created or modified following active exploitation (`timeframe: 600s`) | `kill_chain_installation` | T1505.003<br>T1190 |
| `100209` | 12 | Auditd / Command & Control | Network communication or reverse shell tool spawned by web server user (`nc`, `socat`, `curl`) | `kill_chain_c2` | T1071<br>T1105<br>T1571 |
| `100210` | 14 | Auditd / Chained Escalation | Reverse shell or network utility spawned following exploitation or webshell drop (`timeframe: 600s`) | `kill_chain_c2` | T1071<br>T1105<br>T1190<br>T1571 |
| `100211` | 11 | Access Log / Command & Control | Direct HTTP 200 execution of PHP script located in upload or static directory | `kill_chain_c2` | T1505.003<br>T1071.001<br>T1190 |
| `100212` | 14 | Access Log / Chained Escalation | HTTP 200 interaction with web shell following exploitation or file drop (`timeframe: 600s`) | `kill_chain_c2` | T1505.003<br>T1071.001<br>T1190 |
| `100203` | 10 | Auditd / Actions on Objectives | Command execution spawned under web server user (`www-data`/`apache`/`nginx`) | `kill_chain_actions_on_objectives` | T1059.004 |
| `100208` | 14 | Auditd / Chained Escalation | Shell command spawned by web server user following exploitation, webshell drop, or C2 (`timeframe: 600s`) | `kill_chain_actions_on_objectives` | T1059.004<br>T1190 |

---

## 🌐 Reverse Proxy & Client IP Preservation

> [!IMPORTANT]
> If your web servers reside behind a reverse proxy (Cloudflare, AWS ALB, Nginx Reverse Proxy, HAProxy), correlation rules (`100204`, `100202`) require the **true client IP** in `$(srcip)`. Without proper configuration, all client events will collapse under the proxy's IP, triggering false positive correlations.

### Apache Configuration (`mod_remoteip`):
Ensure `remoteip` module is enabled and configured in `/etc/apache2/conf-available/remoteip.conf` (or `/etc/httpd/conf.d/remoteip.conf`):
```apache
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
LogFormat "%a %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
```

### Nginx Configuration (`ngx_http_realip_module`):
Add to your `http` or `server` block in `/etc/nginx/nginx.conf`:
```nginx
# Standard Internal Subnets & Private Ranges
set_real_ip_from 10.0.0.0/8;
set_real_ip_from 172.16.0.0/12;
set_real_ip_from 192.168.0.0/16;
real_ip_header X-Forwarded-For;
real_ip_recursive on;

# If behind Cloudflare, use CF-Connecting-IP with Cloudflare IP ranges:
# set_real_ip_from 173.245.48.0/20;
# set_real_ip_from 103.21.244.0/22;
# set_real_ip_from 103.22.200.0/22;
# set_real_ip_from 103.31.4.0/22;
# set_real_ip_from 141.101.64.0/18;
# set_real_ip_from 108.162.192.0/18;
# set_real_ip_from 190.93.240.0/20;
# set_real_ip_from 188.114.96.0/20;
# set_real_ip_from 197.234.240.0/22;
# set_real_ip_from 198.41.128.0/17;
# set_real_ip_from 162.158.0.0/15;
# set_real_ip_from 104.16.0.0/13;
# set_real_ip_from 104.24.0.0/14;
# set_real_ip_from 172.64.0.0/13;
# set_real_ip_from 131.0.72.0/22;
# real_ip_header CF-Connecting-IP;
```

---

## 🚀 Deployment Guide

### 1. Wazuh Manager: Deploy Ruleset
1. Copy [`100200-php2shell_rce.xml`](./100200-php2shell_rce.xml) to `/var/ossec/etc/rules/` on the Wazuh Manager:
   ```bash
   cp 100200-php2shell_rce.xml /var/ossec/etc/rules/
   chown root:wazuh /var/ossec/etc/rules/100200-php2shell_rce.xml
   chmod 640 /var/ossec/etc/rules/100200-php2shell_rce.xml
   ```
2. Ensure the CDB list `/var/ossec/etc/lists/audit-keys` contains the audit key mapping for rule `80792` / `100203`:
   ```text
   audit-wazuh-c:command
   ```
3. Test rule syntax:
   ```bash
   /var/ossec/bin/wazuh-analysisd -t
   ```
4. Restart the Wazuh Manager:
   ```bash
   systemctl restart wazuh-manager
   ```

### 2. Wazuh Agent: Ingestion & FIM Configuration
Distribute the configurations from [`agent.conf`](./agent.conf) centrally via `/var/ossec/etc/shared/default/agent.conf` or locally in `/var/ossec/etc/ossec.conf`:

```bash
systemctl restart wazuh-agent
```

### 3. Linux Monitored Hosts: Auditd Setup
Deploy [`auditd.rules`](./auditd.rules) to audit `execve` calls by web users (`euid 33`, `euid 48`, `euid 82`):

```bash
cp auditd.rules /etc/audit/rules.d/wazuh-php2shell.rules
augenrules --load
auditctl -l | grep audit-wazuh-c
```

---

## 🧪 Testing & Validation (`wazuh-logtest`)

Run `/var/ossec/bin/wazuh-logtest` on the Wazuh Manager and verify each test case:

### Test 1: Nginx Error Log (Rule 100200)
```text
2026/10/30 18:22:15 [error] 1234#1234: *1 FastCGI sent in stderr: "PHP message: PHP Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in /var/www/html/upload.php on line 42", client: 198.51.100.25, server: example.com, request: "POST /upload.php HTTP/1.1"
```
* **Evaluation Chain:** `31300` (Nginx) $\to$ `31301` (`[error]`) $\to$ `31402` (PHP Fatal) $\to$ `31420` (PHP Fatal aggregate) $\to$ **`100200` (Level 5)**.

### Test 2: Apache Error Log (Rule 100200)
```text
[Fri Oct 30 18:22:15.123456 2026] [php:error] [pid 1234] [client 198.51.100.25:54321] PHP Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in /var/www/html/index.php on line 12
```
* **Evaluation Chain:** `30100` (Apache) $\to$ `30101` (`^[error]`) $\to$ `31402` (PHP Fatal) $\to$ `31420` $\to$ **`100200` (Level 5)**.

### Test 3: PHP-FPM Direct Syslog (Rule 100200)
```text
Oct 30 18:22:15 webserver php-fpm[1234]: PHP Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in /var/www/html/api.php on line 88
```
* **Evaluation Chain:** `31405` (`^PHP Fatal error:`) $\to$ `31420` $\to$ **`100200` (Level 5)**.

### Test 4: Web Access Log Backend Crash (502/500) (Rule 100205)
```text
198.51.100.25 - - [30/Oct/2026:18:22:15 +0000] "POST /upload.php HTTP/1.1" 502 0 "-" "curl/7.88.1"
```
* **Evaluation Chain:** `31100` (Web log) $\to$ `31120` (5xx Server error) $\to$ **`100205` (Level 5)**.

### Test 5: Post-Exploitation Shell via Auditd (Rule 100203)
```text
type=SYSCALL msg=audit(1761849735.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=55a12b a1=55a180 a2=55a190 a3=0 items=2 ppid=1234 pid=5678 auid=4294967295 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 tty=(none) ses=4294967295 comm="sh" exe="/bin/dash" key="audit-wazuh-c"
```
* **Evaluation Chain:** `80792` (Audit command) $\to$ **`100203` (Level 10)**.

### Test 6: Post-Exploitation Web Shell Drop (Rule 100206)
```text
File '/var/www/html/shell.php' added to the system. Mode: file. Size: 1234 bytes.
```
* **Evaluation Chain:** `554, 550` (FIM file added/modified) $\to$ **`100206` (Level 10)**.

### Test 7: Outbound C2 / Reverse Shell Utility via Auditd (Rule 100209)
```text
type=SYSCALL msg=audit(1761849735.123:457): arch=c000003e syscall=59 success=yes exit=0 a0=55a12b a1=55a180 a2=55a190 a3=0 items=2 ppid=1234 pid=5679 auid=4294967295 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 tty=(none) ses=4294967295 comm="nc" exe="/usr/bin/nc" key="audit-wazuh-c"
```
* **Evaluation Chain:** `80792` (Audit command) $\to$ **`100209` (Level 12)**. If preceded by `100202` or `100206`, escalates to **`100210` (Level 14)**.

### Test 8: Direct HTTP 200 Web Shell Interaction (Rule 100211)
```text
198.51.100.25 - - [30/Oct/2026:18:25:00 +0000] "POST /wp-content/uploads/2026/10/cache.php?cmd=id HTTP/1.1" 200 45 "-" "curl/7.88.1"
```
* **Evaluation Chain:** `31100` (Web log) $\to$ `31108` (2xx/3xx simple request) $\to$ **`100211` (Level 11)**. If preceded by `100202`, `100213`, or `100206`, escalates to **`100212` (Level 14)**.

### Test 9: PHP-FPM Worker Segfault Crash (CVE-2026-109619) (Rule 100213)
```text
Oct 30 18:22:15 webserver php-fpm[1234]: [pool www] child 5678 exited on signal 11 (SIGSEGV) after 12.345678 seconds from start
```
* **Evaluation Chain:** **`100213` (Level 10)**. If followed by webshell upload (`100206`) or shell execution (`100203`), escalates to **Level 14**.

### Test 10: Clean URL / REST API FastCGI Crash (Rule 100205)
```text
198.51.100.25 - - [30/Oct/2026:18:22:15 +0000] "POST /api/v1/attachments/upload HTTP/1.1" 502 0 "-" "curl/7.88.1"
```
* **Evaluation Chain:** `31100` (Web log) $\to$ `31120` (5xx Server error) $\to$ **`100205` (Level 5)**.

---

## ⚙️ False Positive Tuning (Auditd Exclusions)

If your web application legitimately invokes system utilities (e.g. ImageMagick `/usr/bin/convert`, `sendmail`, or PDF generators) from `www-data`, create a local exclusion rule in `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="audit,">
  <!-- Suppress standalone alerts for legitimate web application helper binaries -->
  <rule id="100299" level="0">
    <if_sid>100203</if_sid>
    <field name="audit.exe" type="pcre2">/(?:convert|identify|sendmail|wkhtmltopdf)\z</field>
    <description>Ignore legitimate web helper utilities spawned by web server user</description>
  </rule>
</group>
```

> [!NOTE]
> Because chained escalation rule `100208` requires prior exploitation (`kill_chain_exploitation`), routine background execution of these helper binaries during normal business traffic will never trigger high-severity compromise alerts.

---

## 🐳 Containers, Kubernetes & User Namespaces

When deploying NixWarden rules across containerized environments (Docker, Podman, Kubernetes):

1. **Host-Based vs. Sidecar Agents:**
   - **Inside Container / Sidecar:** Log paths and UIDs match standard Linux conventions (`/var/www/html`, EUID `33` or `82`).
   - **Host-Based / Kubernetes Node:** The host kernel executes Auditd and FIM. Web roots will reside inside container storage driver overlays (e.g. `/var/lib/docker/overlay2/.../var/www/...` or `/run/containerd/...`). Rule `100206` is specifically engineered without strict prefix anchors to match both native host and container overlay paths seamlessly.
2. **User Namespace Remapping (UID Subordinate Ranges):**
   - If Docker or containerd has User Namespaces enabled (`userns-remap`), the container's `www-data` (UID `33`) is remapped to a subordinate UID on the host (e.g. `100033`).
   - In such environments, adjust `auditd.rules` on the host to match your cluster's remapped UID range, or deploy the Wazuh agent directly into the container/pod namespace.
3. **CRI Log Prefix Handling (Kubernetes Pod Logs):**
   - Kubernetes container logs at `/var/log/pods/*/*/*.log` prepend CRI log headers (`<timestamp> <stream> <flag>`). Configure log collectors with `<log_format>syslog</log_format>` or container-aware decoders to forward unwrapped payloads to `analysisd`.

---

## 🏢 Multi-Tenant & Shared Hosting Environments

In multi-tenant hosting environments (cPanel, Plesk, CloudLinux):
- PHP-FPM pools run under individual customer accounts (UID >= 1000) rather than a single `www-data` or `apache` user.
- To monitor all customer pools with Linux Auditd, configure audit rules to target the web server execution group or UID floor:
  ```bash
  # Monitor all non-system user executions spawned by FastCGI workers
  -a always,exit -F arch=b64 -S execve -F euid>=1000 -k audit-wazuh-c
  ```

## 🛠️ Remediation & Mitigation

> [!CAUTION]
> Detection rules provide detection in-depth and incident visibility. **Upgrading PHP is the only complete remediation.**

1. **Apply Official Patches:**
   * **PHP 8.5:** Version `8.5.12` or higher
   * **PHP 8.4:** Version `8.4.27` or higher
   * **PHP 8.3:** Version `8.3.36` or higher
   * **PHP 8.2:** Version `8.2.35` or higher
2. **Restart Web Workers:** Always restart `apache2`, `httpd`, and `php-fpm` following package upgrades:
   ```bash
   systemctl restart php*-fpm apache2 httpd nginx
   ```
3. **Temporary Workaround (if patching is deferred):**
   Disable session upload progress in `php.ini`:
   ```ini
   session.upload_progress.enabled = 0
   ```
