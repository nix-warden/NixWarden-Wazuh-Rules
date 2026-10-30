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
                                              - 100200: Precursor (OOM)
                                              - 100201: Precursor (Timeout)
                                              - 100204: Probing (3 in 60s)
                                              - 100202: Active Exploit (5 in 120s)
```

### Telemetry Vectors:
1. **Vector 1 (Web Error Logs):** Catches OOM and timeout precursors across Nginx, Apache, and direct PHP-FPM logs via parent `31420`.
2. **Vector 2 (Web Access Logs):** Correlates HTTP 500 server error spikes on `.php` endpoints via `31122` (from `0245-web_rules.xml`).
3. **Vector 3 (Host Audit Telemetry):** Intercepts post-exploitation shell spawning by web server users (`www-data`, `apache`, `nginx`, `nobody`) via Linux `auditd` and rule `80792`.
4. **Vector 4 (File Integrity Monitoring):** Real-time detection of dropped web shells (`.php`, `.phtml`, `.phar`, `.so`) in `/var/www/html` via Wazuh FIM (`syscheck`, rule `554`).

---

## 📋 Rule Catalog

All rules are assigned to the **NixWarden Web Application Security namespace (`100,200 - 100,250`)**:

| Rule ID | Level | Vector / Type | Description | Cyber Kill Chain | MITRE ATT&CK |
|---|---|---|---|---|---|
| `100200` | 5 | Error Log / Precursor | Single PHP memory exhaustion fatal error (`Allowed memory size...`) | `kill_chain_delivery`<br>`kill_chain_exploitation` | T1190<br>T1499.003 |
| `100201` | 5 | Error Log / Precursor | Single PHP execution timeout fatal error (`Maximum execution time...`) | `kill_chain_delivery`<br>`kill_chain_exploitation` | T1190 |
| `100204` | 8 | Error Log / Correlation | Repeated memory exhaustion probing (3 events in 60s from same IP) | `kill_chain_reconnaissance`<br>`kill_chain_delivery` | T1595.002<br>T1190 |
| `100202` | 12 | Error Log / Correlation | High-frequency memory exhaustion (5 events in 120s). Active RCE exploit attempt. | `kill_chain_exploitation` | T1190<br>T1499.003 |
| `100205` | 5 | Access Log / Correlation | HTTP 500 Internal Error on `.php` endpoint (potential engine crash) | `kill_chain_exploitation` | T1190 |
| `100203` | 10 | Auditd / Post-Exploit | Command execution spawned under web server user (`www-data`/`apache`/`nginx`) | `kill_chain_actions_on_objectives` | T1059.004 |
| `100206` | 10 | FIM / Post-Exploit | New executable script (`.php`, `.phtml`, `.so`) created in web root | `kill_chain_installation` | T1505.003 |

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
set_real_ip_from 10.0.0.0/8;
set_real_ip_from 172.16.0.0/12;
set_real_ip_from 192.168.0.0/16;
real_ip_header X-Forwarded-For;
real_ip_recursive on;
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

### Test 4: Web Access Log 500 Crash (Rule 100205)
```text
198.51.100.25 - - [30/Oct/2026:18:22:15 +0000] "POST /upload.php HTTP/1.1" 500 0 "-" "curl/7.88.1"
```
* **Evaluation Chain:** `31100` (Web log) $\to$ `31120` (5xx) $\to$ `31122` (500 Internal Error) $\to$ **`100205` (Level 5)**.

### Test 5: Post-Exploitation Shell via Auditd (Rule 100203)
```text
type=SYSCALL msg=audit(1761849735.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=55a12b a1=55a180 a2=55a190 a3=0 items=2 ppid=1234 pid=5678 auid=4294967295 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 tty=(none) ses=4294967295 comm="sh" exe="/bin/dash" key="audit-wazuh-c"
```
* **Evaluation Chain:** `80792` (Audit command) $\to$ **`100203` (Level 10)**.

### Test 6: Post-Exploitation Web Shell Drop (Rule 100206)
```text
File '/var/www/html/shell.php' added to the system. Mode: file. Size: 1234 bytes.
```
* **Evaluation Chain:** `554` (FIM file added) $\to$ **`100206` (Level 10)**.

---

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
