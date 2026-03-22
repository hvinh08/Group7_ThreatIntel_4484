# BazarLoader — Malware Case Study

**Course:** EECS 4484 — Computer Security  
**Authors:** Victor Hoac (219828854), Hoang Vinh Nguyen (219420512)  
**Date:** March 22, 2025

## Overview

This repository contains the technical deliverables from our case study on **BazarLoader** (a.k.a. Bazar, Bazaloader, KEGTAP, Team9) — a downloader and backdoor malware linked to TrickBot infrastructure and attributed to Wizard Spider, EXOTIC LILY, and TA551. BazarLoader was active from April 2020 to February 2022, after which it was succeeded by Bumblebee.

## Repository Contents

| File | Description |
|------|-------------|
| `bazarloader_stix_iocs.json` | STIX 2.1 bundle containing all Indicators of Compromise (IoCs) extracted from the report — C2 domains, IP addresses, URI patterns, file hashes, registry keys, TLS certificates, and behavioral process indicators |
| `bazarloader_yara_rules.yar` | Two YARA detection rules: one targeting the EnterDLL export and C2 URI patterns, and another targeting the process hollowing API sequence with BCryptDecrypt usage |
| `bazarloader_mitre_attack.json` | MITRE ATT&CK Navigator layer mapping the 13 techniques observed in BazarLoader's execution chain |

## Indicators of Compromise Summary

**Network IoCs**
- 5 C2 domains (forgame.bazar, bestgame.bazar, englewoodcarwash.us, gojihu.com, yuxicu.com)
- 2 C2 IP addresses (104.248.174.225, 104.248.166.170)
- 3 C2 URI patterns (/data/service, /stat/var/upd, /cgi-bin/req5)
- 1 TLS certificate indicator (amadeamadey.at)
- 1 spoofed user-agent string

**Host IoCs**
- 2 SHA-256 sample hashes
- 3 registry key persistence paths
- 6 behavioral process indicators (svchost.exe parent mismatch, cmd.exe hollowing, nltest/net.exe reconnaissance, certutil decode, rundll32 EnterDLL)

## MITRE ATT&CK Techniques

| ID | Technique | Tactic |
|----|-----------|--------|
| T1566.002 | Phishing: Spearphishing Link | Initial Access |
| T1106 | Native API | Execution |
| T1047 | Windows Management Instrumentation | Execution |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence |
| T1547.009 | Shortcut Modification | Persistence |
| T1055.013 | Process Injection: Process Hollowing | Privilege Escalation |
| T1140 | Deobfuscate/Decode Files or Information | Defense Evasion |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion |
| T1036.004 | Masquerading: Double File Extension | Defense Evasion |
| T1027.002 | Obfuscated Files or Information: Software Packing | Defense Evasion |
| T1497.003 | Virtualization/Sandbox Evasion: Time-Based Checks | Defense Evasion |
| T1005 | Data from Local System | Collection |
| T1104 | Multi-Stage Channels | Command and Control |

## Tools Used

- **STIX 2.1 bundle** generated using the [cti-python-stix2](https://github.com/oasis-open/cti-python-stix2) library
- **YARA rules** written manually based on behavioral and static analysis from referenced sources
- **MITRE ATT&CK mapping** created using the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

## References

1. [Cybereason — A Bazar of Tricks](https://www.cybereason.com/blog/research/a-bazar-of-tricks-following-team9s-development-cycles)
2. [MITRE ATT&CK — BazarLoader (S0534)](https://attack.mitre.org/software/S0534/)
3. [Unit 42 — BazarLoader Malware](https://unit42.paloaltonetworks.com/bazarloader-malware/)
4. [Fortinet — New Bazar Trojan Variant](https://www.fortinet.com/blog/threat-research/new-bazar-trojan-variant-is-being-spread-in-recent-phishing-campaign-part-I)
5. [AT&T AlienLabs — TrickBot BazarLoader In-Depth](https://cybersecurity.att.com/blogs/labs-research/trickbot-bazarloader-in-depth)
6. [Sophos — BazarLoader](https://news.sophos.com/en-us/2021/04/15/bazarloader/)
7. [Trend Micro — BazarLoader Delivery Vectors](https://www.trendmicro.com/en_us/research/21/k/bazarloader-adds-compromised-installers-iso-to-arrival-delivery-vectors.html)
