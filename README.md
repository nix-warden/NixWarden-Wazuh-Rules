# NixWarden-Wazuh-Rules 🛡️

## 📖 The Golden Ruleset for Autonomous SOC

**NixWarden-Wazuh-Rules** is a curated and hardened repository of detection rules for Wazuh. Unlike standard community forks, this repository follows the **"Golden Ruleset" philosophy**: every rule is filtered, syntax-validated, and mapped to the **MITRE ATT&CK framework**.

## 🧠 Rule ID Strategy & Namespace Management

To prevent `Wazuh-Manager` service failures due to duplicate Rule IDs, this repository strictly adheres to a custom ID namespace.

### The Namespace Convention

- **0 - 99,999:** Reserved for standard, default Wazuh rules. **DO NOT USE.**
- **100,000 - 199,999:** Reserved for **NixWarden-Wazuh-Rules** (custom & adapted detections).
    - **100,000 - 100,029:** Reserved for **local_rules.xml**
    - **100,030 - 100,100** Reserved for **Custom AWS rules**
- **200,000+:** Reserved for custom/local overrides and enterprise extensions.

### Out-of-the-Box Exceptions (> 100,000)

Wazuh includes several default rule ranges that exceed the standard `99,999` limit. To prevent collisions, the following ranges are reserved by Wazuh and **must not be used**:

- **150,100 - 150,150:** Reserved for Wazuh FireEye rules.
- **182,013 - 185,000:** Reserved for Wazuh Sysmon rules.
- **184,665 - 184,777:** Reserved for Wazuh Sysmon rules.
- **500,000 - 500,102:** Reserved for Wazuh Unbound rules.

_Before deploying, always check your `/var/ossec/etc/rules/` directory to ensure no local collisions exist._
## 🚀 Key Features

- **MITRE ATT&CK Mapping:** Every rule includes `<mitre>` tags for consistent threat hunting.
    
- **Clean Room Design:** We don't blindly copy-paste; we adapt logic to ensure performance optimization for high-load environments.
    

## ⚖️ Compliance & Attribution

This repository is a curated collection. While we write original rules, we also adapt and optimize community-driven detection logic.

- **Source Attribution:** This project incorporates detection logic inspired by [SOCFortress](https://github.com/socfortress/Wazuh-Rules) and other community contributors. We acknowledge their foundational work in the open-source SIEM community.
    
- **License:** This repository is released under the **MIT License**. Note that while our structural work and custom rules are MIT, individual rule adaptations remain subject to their respective original licenses where applicable. See LICENSE.md for details.
    

_Contributions are welcome. Please open an issue or pull request to suggest new detections._
