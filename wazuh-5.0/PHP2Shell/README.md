# NixWarden — PHP2Shell Detection Suite for Wazuh 5.0 (RC)

Enterprise detection suite for **PHP2Shell Remote Code Execution** ([CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618), [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619)) designed natively for **Wazuh 5.0 (Sigma / Wazuh Common Schema - WCS)**.

---

## 1. Paradigm Shift: Wazuh 4.x vs Wazuh 5.0

| Feature | Wazuh 4.x (Legacy) | Wazuh 5.0 (Sigma / WCS) |
| :--- | :--- | :--- |
| **Rule Format** | Proprietary XML (`<rule id="..." level="...">`) | Standard Sigma YAML (`title:`, `detection:`, `level:`) |
| **Field Parsing** | Regex Decoders (`decoders/*.xml`) | Wazuh Common Schema (WCS / ECS-compliant) |
| **Inheritance & Hierarchy** | Parent IDs (`<if_sid>31100</if_sid>`) | Atomic rules matched against normalized schema fields |
| **Multi-Stage Correlation** | State engine (`<timeframe>`, `<same_source_ip/>`) | **Sigma Correlation Rules** (`type: temporal`, `event_count`) |
| **Cross-Source Chaining** | Very difficult (Syslog and Auditd have separate trees) | Seamless across all log types (`host.name`, `source.ip`) |
| **Threat Taxonomies** | Custom XML tags (`<mitre>`, `<group>`) | Native standard tags (`attack.*`, `ckc.*`, `kill_chain.*`) |

---

## 2. Rule Catalog & 4.14 Mapping Matrix

### Atomic Sigma Rules (`wazuh-5.0/PHP2Shell/rules/`)

| 4.x SID | Wazuh 5.0 File | Sigma UUID | Kill Chain Phase | MITRE ATT&CK | Level | Description |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| `100200` | `delivery_php_memory_exhaustion.yml` | `91414b3d-...` | `ckc.delivery` | `T1190`, `T1499.003` | Low | Fatal PHP memory exhaustion error |
| `100201` | `delivery_php_timeout.yml` | `7df01780-...` | `ckc.delivery` | `T1190` | Low | PHP maximum execution time exceeded |
| `100205` | `delivery_fastcgi_backend_crash.yml` | `d95b7dc1-...` | `ckc.delivery` | `T1190` | Low | FastCGI backend death (HTTP 502/504) |
| `100214` | `delivery_php_upload_http_500.yml` | `7f9c05d4-...` | `ckc.delivery` | `T1190` | Low | HTTP 500/503 on PHP or upload routes |
| `100213` | `exploit_php_fpm_worker_crash.yml` | `a01b2fa5-...` | `ckc.exploitation` | `T1190`, `T1499.003` | High | PHP-FPM pool worker SIGSEGV/SIGABRT |
| `100215` | `exploit_kernel_php_segfault.yml` | `b17504fc-...` | `ckc.exploitation` | `T1190`, `T1499.003` | High | Linux kernel segfault in PHP process |
| `100206` | `install_webshell_drop_fim.yml` | `96292cfd-...` | `ckc.installation` | `T1505.003` | High | Executable script created/modified in web root |
| `100209` | `c2_auditd_reverse_shell.yml` | `f1b33ff9-...` | `ckc.command_and_control` | `T1071`, `T1105`, `T1571` | High | Outbound network tool spawned by web user |
| `100211` | `c2_web_shell_interaction_200.yml` | `7c131c82-...` | `ckc.command_and_control` | `T1505.003`, `T1071.001` | High | HTTP 200 interaction with script in upload dir |
| `100203` | `actions_auditd_shell_execution.yml` | `5d155b03-...` | `ckc.actions_on_objectives`| `T1059.004` | High | Shell interpreter spawned by web user |

---

### Sigma Correlation Rules (`wazuh-5.0/PHP2Shell/correlations/`)

| 4.x SID | Correlation File | Type | Window | Group By | Level | Escalation Criteria |
| :---: | :--- | :---: | :---: | :--- | :---: | :--- |
| `100204` | `recon_delivery_probing_frequency.yml` | `event_count` | 60s | `source.ip` | Medium | $\ge 3$ delivery anomalies from same IP |
| `100202` | `exploit_memory_exhaustion_frequency.yml`| `event_count` | 120s | `source.ip` | High | $\ge 5$ memory exhaustions from same IP |
| `100207` | `correlation_exploit_to_webshell_install.yml` | `temporal` | 10m | `host.name` | Critical | Worker crash/segfault $\to$ Web shell dropped (FIM) |
| `100210` | `correlation_exploit_to_c2_reverse_shell.yml` | `temporal` | 15m | `host.name` | Critical | Exploit/Drop $\to$ Outbound reverse shell (Auditd) |
| `100212` | `correlation_exploit_to_webshell_access.yml` | `temporal` | 15m | `host.name` | Critical | Exploit/Drop $\to$ HTTP 200 upload execution |
| `100208` | `correlation_exploit_to_actions_shell_exec.yml` | `temporal` | 15m | `host.name` | Critical | Exploit/Drop/C2 $\to$ Shell command execution |
| *New* | `correlation_php2shell_full_killchain.yml` | `temporal_ordered` | 30m | `host.name` | Critical | Complete Kill Chain progression |

---

## 3. Tagging & Taxonomy Architecture

Every rule adheres strictly to the official **Wazuh 5.0 / Sigma Standard Taxonomy**:

```yaml
tags:
    # Official Sigma & Wazuh 5.0 Standard (Populates Threat Intel & MITRE Matrices)
    - attack.initial_access
    - attack.t1190
    - ckc.delivery
    - php2shell
```

### Benefits:
1. **Out-of-the-box Dashboard Visualizations**: Wazuh 5.0 native MITRE ATT&CK and Cyber Kill Chain views automatically index and map `attack.*` and `ckc.*`.
2. **Lean Metadata**: Eliminates duplicated or non-standard tag fields, keeping events clean and compliant with open standards.

---

## 4. Wazuh Common Schema (WCS) Field Mapping

All Sigma rules evaluate directly against normalized fields in the indexer:

| Field Name | Type | Example Values | Used In |
| :--- | :--- | :--- | :--- |
| `http.response.status_code` | `long` | `200`, `500`, `502`, `504` | Web server access/error logs |
| `url.path` | `keyword` | `/wp-content/uploads/shell.php` | Web server access logs |
| `message` | `text` | `Allowed memory size of 134217728 bytes exhausted` | PHP-FPM, Syslog, Dmesg |
| `file.path` | `keyword` | `/var/www/html/uploads/payload.php` | Wazuh FIM (Syscheck) |
| `event.action` | `keyword` | `created`, `modified`, `file_created` | Wazuh FIM events |
| `user.effective.id` | `long` | `33` (`www-data`), `48` (`apache`), `82` (`nginx`) | Auditd process execution |
| `user.effective.name` | `keyword` | `www-data`, `apache`, `nginx` | Auditd process execution |
| `process.executable` | `keyword` | `/usr/bin/nc`, `/bin/bash`, `/usr/bin/python3` | Auditd process execution |
| `host.name` | `keyword` | `web-prod-01.domain.internal` | Correlation grouping key |
| `source.ip` | `ip` | `203.0.113.50` | Correlation grouping key |

---

## 5. Deployment Guide for Wazuh 5.0

### Method A: Via Wazuh 5.0 Dashboard (Content Manager)
1. Navigate to **Server Management $\to$ Detection $\to$ Rules**.
2. Select **Import Rules** $\to$ upload files from `wazuh-5.0/PHP2Shell/rules/`.
3. Set rule lifecycle state to **Test** (for verification) or **Production**.
4. Navigate to **Detection $\to$ Correlations** $\to$ **Import Correlation Rules**.
5. Upload correlation files from `wazuh-5.0/PHP2Shell/correlations/`.
6. Click **Apply Changes** to hot-reload the indexer detection engine.

### Method B: Via Wazuh 5.0 REST API
```bash
# Set your Wazuh 5.0 Manager URL and Token
WAZUH_API="https://wazuh-manager.example.com:55000"
TOKEN="YOUR_AUTH_BEARER_TOKEN"

# 1. Bulk import atomic Sigma rules
for rule in wazuh-5.0/PHP2Shell/rules/*.yml; do
  curl -k -X POST "$WAZUH_API/api/v1/content/rules" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/yaml" \
    --data-binary "@$rule"
done

# 2. Bulk import Sigma correlation rules
for corr in wazuh-5.0/PHP2Shell/correlations/*.yml; do
  curl -k -X POST "$WAZUH_API/api/v1/content/correlations" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/yaml" \
    --data-binary "@$corr"
done

# 3. Reload detection engine
curl -k -X POST "$WAZUH_API/api/v1/engine/reload" \
  -H "Authorization: Bearer $TOKEN"
```

---

## 6. Verification and Testing

You can validate Sigma rules locally using the open-source `sigma-cli` tool:

```bash
# Install sigma-cli (if not already installed)
pip install sigma-cli

# Validate syntax of all rules
sigma check wazuh-5.0/PHP2Shell/rules/
sigma check wazuh-5.0/PHP2Shell/correlations/
```

### Test Scenarios:
1. **Worker Crash (Exploit Stage):**
   - Ingest message: `[pool www] child 14208 exited on signal 11 (SIGSEGV) after 15.234120 seconds from start`.
   - **Expectation:** Fires `a01b2fa5-d615-4a62-8d73-ebe7a039de7c` (`exploit_php_fpm_worker_crash.yml`, Level High).
2. **Webshell Implant (Installation Stage):**
   - Ingest FIM event: `file.path: "/var/www/html/uploads/payload.php"`, `event.action: "created"`.
   - **Expectation:** Fires `96292cfd-9c84-48bd-8beb-31109ed52f4b` (`install_webshell_drop_fim.yml`, Level High).
3. **Escalation Incident:**
   - Both events occur on host `webserver` within 10 minutes.
   - **Expectation:** Temporal correlation engine fires `d69b9850-fff9-49cd-bfcb-74a93fe4a7b8` (`correlation_exploit_to_webshell_install.yml`, Level **Critical**).

