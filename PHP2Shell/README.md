# PHP2Shell Detection Ruleset (CVE-2026-109618 & CVE-2026-109619) 🛡️

This directory contains detection rules, agent configurations, and audit policies for identifying exploitation attempts and post-compromise activity associated with the **PHP2Shell** vulnerabilities using **Wazuh SIEM/XDR**.

> [!NOTE]
> Based on the official Wazuh research: [Detecting PHP2Shell remote code execution with Wazuh](https://wazuh.com/blog/detecting-php2shell-remote-code-execution-with-wazuh/).

---

## 🔍 Vulnerability Overview

**PHP2Shell** consists of two critical memory-safety vulnerabilities in the core PHP engine with a **CVSS v4.0 score of 9.2**:

* **CVE-2026-109618:** Flaw in out-of-memory (OOM) error handling via `longjmp()`. When request allocation fails prior to full memory initialization, request cleanup reads uninitialized memory, enabling unauthenticated Remote Code Execution (RCE).
* **CVE-2026-109619:** Stale global state vulnerability where fatal errors leave dangling pointers to freed request memory (e.g., in `session.upload_progress` and backtraces), reused by subsequent operations in persistent worker processes.

Because these flaws reside in the core PHP runtime interpreter (affecting Apache `mod_php` and `PHP-FPM`), they execute **before any application-level framework code** (WordPress, Drupal, Laravel) runs, making conventional WAF rules and application logging insufficient on their own.

---

## 🎯 Multi-Layered Detection Strategy

Wazuh detects PHP2Shell through a 3-layer defense-in-depth model:

```
+-------------------------------------------------------------------------+
| Layer 1: Exploit Precursors & Probing (Web Server / PHP Error Logs)     |
| Rules: 100200, 100201, 100202                                           |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Layer 2: File Integrity Monitoring (FIM / Syscheck)                     |
| Real-time detection of dropped webshells in /var/www/html or /tmp       |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Layer 3: Post-Exploitation Execution (Linux Auditd)                     |
| Rule: 100203 - Detects child shell/commands spawned by web server user  |
+-------------------------------------------------------------------------+
```

---

## 📋 Rule Catalog

All rules in this set belong to the **NixWarden Web Application Security pool (`100,200 - 100,250`)**:

| Rule ID | Level | Type | Description | MITRE ATT&CK |
|---|---|---|---|---|
| `100200` | 7 | Precursor | Detects PHP fatal error: `Allowed memory size of ... bytes exhausted` | T1190, T1499.003 |
| `100201` | 7 | Precursor | Detects PHP fatal error: `Maximum execution time of ... seconds exceeded` | T1190 |
| `100202` | 12 | Correlation | Multiple (5+) memory exhaustion errors from same source IP within 120s | T1190, T1499.003 |
| `100203` | 10 | Post-Exploitation | Command execution spawned by web server process user (`www-data`/`apache`) | T1059.004 |

---

## 🚀 Deployment Guide

### 1. Wazuh Manager: Deploy Detection Rules
1. Copy [`100200-php2shell_rce.xml`](./100200-php2shell_rce.xml) to `/var/ossec/etc/rules/` on your Wazuh Manager:
   ```bash
   cp 100200-php2shell_rce.xml /var/ossec/etc/rules/
   chown root:wazuh /var/ossec/etc/rules/100200-php2shell_rce.xml
   chmod 640 /var/ossec/etc/rules/100200-php2shell_rce.xml
   ```
2. Verify rule syntax:
   ```bash
   /var/ossec/bin/wazuh-analysisd -t
   ```
3. Restart the Wazuh Manager:
   ```bash
   systemctl restart wazuh-manager
   ```

### 2. Wazuh Agent: Configure Log Ingestion & FIM
Apply the configurations from [`agent.conf`](./agent.conf) either centrally via `/var/ossec/etc/shared/default/agent.conf` or locally on monitored endpoints in `/var/ossec/etc/ossec.conf`:

* **Log collection:** Ingests Apache error logs (`/var/log/apache2/error.log` or `/var/log/httpd/error_log`), PHP-FPM logs, and `audit.log`.
* **FIM (Syscheck):** Monitors `/var/www/html` and `/tmp` with `realtime="yes"`.

Restart the agent after applying:
```bash
systemctl restart wazuh-agent
```

### 3. Monitored Linux Endpoint: Configure Auditd
Copy [`auditd.rules`](./auditd.rules) to `/etc/audit/rules.d/wazuh-php2shell.rules` to audit `execve` calls for web server users (`euid 33` for `www-data`, `euid 48` for `apache`):

```bash
cp auditd.rules /etc/audit/rules.d/wazuh-php2shell.rules
augenrules --load
```

Verify the rules are active:
```bash
auditctl -l | grep audit-wazuh-c
```

---

## 🧪 Testing & Validation

### Validate Rules with `wazuh-logtest`
Run `/var/ossec/bin/wazuh-logtest` on the Wazuh Manager and paste test log lines:

#### Test 1: Single Memory Exhaustion (Rule 100200)
```text
[Fri Oct 30 18:22:15.123456 2026] [php:error] [pid 1234] [client 198.51.100.25:54321] PHP Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in /var/www/html/index.php on line 12
```
*Expected Output:* Matches rule `30301`, then fires rule `100200` (Level 7).

#### Test 2: Execution Timeout (Rule 100201)
```text
[Fri Oct 30 18:22:20.123456 2026] [php:error] [pid 1234] [client 198.51.100.25:54321] PHP Fatal error: Maximum execution time of 30 seconds exceeded in /var/www/html/upload.php on line 45
```
*Expected Output:* Matches rule `30301`, then fires rule `100201` (Level 7).

#### Test 3: Post-Exploitation Command Spawn (Rule 100203)
```text
type=SYSCALL msg=audit(1761849735.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=55a12b a1=55a180 a2=55a190 a3=0 items=2 ppid=1234 pid=5678 auid=4294967295 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 tty=(none) ses=4294967295 comm="sh" exe="/bin/dash" key="audit-wazuh-c"
```
*Expected Output:* Fires rule `100203` (Level 10) for unauthorized shell spawn by `www-data`.

---

## 🛠️ Remediation & Patching

> [!IMPORTANT]
> Detection rules provide compensatory visibility while patching. **They do not replace upgrading PHP.**

1. **Upgrade PHP:** Update to patched releases:
   * **PHP 8.5:** `8.5.12` or higher
   * **PHP 8.4:** `8.4.27` or higher
   * **PHP 8.3:** `8.3.36` or higher
   * **PHP 8.2:** `8.2.35` or higher
2. **Restart Web Workers:** Always restart `apache2`, `httpd`, or `php-fpm` after updating packages. Running worker processes will retain vulnerable builds in memory until restarted:
   ```bash
   systemctl restart php*-fpm apache2 httpd
   ```
3. **Temporary Workaround (if immediate upgrade is impossible):**
   Disable session upload progress in `php.ini`:
   ```ini
   session.upload_progress.enabled = 0
   ```
