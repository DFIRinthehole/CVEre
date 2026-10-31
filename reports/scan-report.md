# CVEre report

Generated 2026-10-31T13:37:14Z · 20 CVEs · 18 with public PoC · 2 in CISA KEV

## Services

| host | port | service | banner | CPE |
|---|---|---|---|---|
| web01.lab.local | 22/tcp | ssh | OpenSSH 8.2p1 | cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:* |
| web01.lab.local | 80/tcp | http | Apache httpd 2.4.49 | cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:* |
| web01.lab.local | 3306/tcp | mysql | MySQL 5.7.31 | cpe:2.3:a:oracle:mysql:5.7.31:*:*:*:*:*:*:* |
| 10.10.14.22 | 6379/tcp | redis | Redis key-value store 6.0.9 | cpe:2.3:a:redis:redis:6.0.9:*:*:*:*:*:*:* |
| 10.10.14.22 | 8080/tcp | http-proxy | Jetty 9.4.43 | cpe:2.3:a:eclipse:jetty:9.4.43:*:*:*:*:*:*:* |

## Findings

| CVE | Severity | CVSS | EPSS | KEV | PoCs | Sources |
|---|---|---|---|---|---|---|
| [CVE-2025-49844](https://nvd.nist.gov/vuln/detail/CVE-2025-49844) | CRITICAL | 9.9 | 82.6% | - | 31 | poc-in-github, nuclei, trickest |
| [CVE-2021-41773](https://nvd.nist.gov/vuln/detail/CVE-2021-41773) | CRITICAL | 9.8 | 100.0% | yes | 48 | poc-in-github, exploitdb, metasploit, nuclei, hackerone, vulhub, trickest |
| [CVE-2021-42013](https://nvd.nist.gov/vuln/detail/CVE-2021-42013) | CRITICAL | 9.8 | 100.0% | yes | 48 | poc-in-github, exploitdb, metasploit, nuclei, hackerone, vulhub, trickest |
| [CVE-2021-44790](https://nvd.nist.gov/vuln/detail/CVE-2021-44790) | CRITICAL | 9.8 | 96.8% | - | 22 | poc-in-github, exploitdb, trickest |
| [CVE-2023-38408](https://nvd.nist.gov/vuln/detail/CVE-2023-38408) | CRITICAL | 9.8 | 79.7% | - | 28 | poc-in-github, trickest |
| [CVE-2022-22720](https://nvd.nist.gov/vuln/detail/CVE-2022-22720) | CRITICAL | 9.8 | 28.2% | - | 19 | trickest |
| [CVE-2026-60002](https://nvd.nist.gov/vuln/detail/CVE-2026-60002) | CRITICAL | 9.4 | 0.3% | - | 0 | - |
| [CVE-2026-2332](https://nvd.nist.gov/vuln/detail/CVE-2026-2332) | CRITICAL | 9.1 | 1.3% | - | 4 | poc-in-github, trickest |
| [CVE-2022-24834](https://nvd.nist.gov/vuln/detail/CVE-2022-24834) | HIGH | 8.8 | 41.4% | - | 10 | trickest |
| [CVE-2021-32626](https://nvd.nist.gov/vuln/detail/CVE-2021-32626) | HIGH | 8.8 | 16.2% | - | 3 | trickest |
| [CVE-2021-32762](https://nvd.nist.gov/vuln/detail/CVE-2021-32762) | HIGH | 8.8 | 2.6% | - | 1 | trickest |
| [CVE-2026-10050](https://nvd.nist.gov/vuln/detail/CVE-2026-10050) | HIGH | 8.7 | 0.6% | - | 2 | trickest |
| [CVE-2026-35385](https://nvd.nist.gov/vuln/detail/CVE-2026-35385) | HIGH | 8.1 | 0.6% | - | 0 | - |
| [CVE-2026-35414](https://nvd.nist.gov/vuln/detail/CVE-2026-35414) | HIGH | 8.1 | 0.2% | - | 1 | poc-in-github |
| [CVE-2025-5115](https://nvd.nist.gov/vuln/detail/CVE-2025-5115) | HIGH | 7.7 | 3.6% | - | 3 | trickest |
| [CVE-2022-2048](https://nvd.nist.gov/vuln/detail/CVE-2022-2048) | HIGH | 7.5 | 2.6% | - | 2 | trickest |
| [CVE-2023-21980](https://nvd.nist.gov/vuln/detail/CVE-2023-21980) | HIGH | 7.1 | 0.8% | - | 1 | trickest |
| [CVE-2020-14765](https://nvd.nist.gov/vuln/detail/CVE-2020-14765) | MEDIUM | 6.5 | 3.2% | - | 8 | trickest |
| [CVE-2020-14769](https://nvd.nist.gov/vuln/detail/CVE-2020-14769) | MEDIUM | 6.5 | 2.5% | - | 8 | trickest |
| [CVE-2020-14775](https://nvd.nist.gov/vuln/detail/CVE-2020-14775) | MEDIUM | 6.5 | 2.5% | - | 2 | trickest |

### CVE-2025-49844 — CRITICAL 9.9

*Matched on:* Redis key-value store 6.0.9 @ 10.10.14.22:6379/tcp

Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

| Source | What | Link |
|---|---|---|
| poc-in-github | raminfp/redis_exploit | https://github.com/raminfp/redis_exploit |
| poc-in-github | cc3305/CVE-2025-49844 | https://github.com/cc3305/CVE-2025-49844 |
| poc-in-github | Cilectiy/CVE-2025-49844 | https://github.com/Cilectiy/CVE-2025-49844 |
| poc-in-github | 0xAshwesker/CVE-2025-49844 | https://github.com/0xAshwesker/CVE-2025-49844 |
| poc-in-github | zbyszkok/CVE-2025-49844-RediShell-AI-made-Revshell | https://github.com/zbyszkok/CVE-2025-49844-RediShell-AI-made-Revshell |
| poc-in-github | Network-Sec/CVE-2025-49844-RediShell-AI-made-Revshell | https://github.com/Network-Sec/CVE-2025-49844-RediShell-AI-made-Revshell |
| poc-in-github | saneki/cve-2025-49844 | https://github.com/saneki/cve-2025-49844 |
| poc-in-github | B1ack4sh/Blackash-CVE-2025-49844 | https://github.com/B1ack4sh/Blackash-CVE-2025-49844 |
| poc-in-github | elyasbassir/CVE-2025-49844 | https://github.com/elyasbassir/CVE-2025-49844 |
| poc-in-github | angelusrivera/CVE-2025-49844 | https://github.com/angelusrivera/CVE-2025-49844 |
| poc-in-github | Mufti22/CVE-2025-49844-RediShell-Vulnerability-Scanner | https://github.com/Mufti22/CVE-2025-49844-RediShell-Vulnerability-Scanner |
| poc-in-github | YuanBenSir/CVE-2025-49844_POC | https://github.com/YuanBenSir/CVE-2025-49844_POC |
| poc-in-github | Yuri08loveElaina/CVE-2025-49844 | https://github.com/Yuri08loveElaina/CVE-2025-49844 |
| poc-in-github | srozb/reditrap | https://github.com/srozb/reditrap |
| poc-in-github | dwisiswant0/CVE-2025-49844 | https://github.com/dwisiswant0/CVE-2025-49844 |
| poc-in-github | Zain3311/CVE-2025-49844 | https://github.com/Zain3311/CVE-2025-49844 |
| poc-in-github | ksnnd32/redis_exploit | https://github.com/ksnnd32/redis_exploit |
| nuclei | Redis Lua Parser < 8.2.2 - Use After Free | https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/javascript/cves/2025/CVE-2025-49844.yaml |
| trickest | https://github.com/AlexRogalskiy/AlexRogalskiy | https://github.com/AlexRogalskiy/AlexRogalskiy |
| trickest | https://github.com/CrackerCat/feed | https://github.com/CrackerCat/feed |
| trickest | https://github.com/GhostTroops/TOP | https://github.com/GhostTroops/TOP |
| trickest | https://github.com/Ian729/HackerNewsArchive | https://github.com/Ian729/HackerNewsArchive |
| trickest | https://github.com/gopinaath/CVE-2025-49844-discovery | https://github.com/gopinaath/CVE-2025-49844-discovery |
| trickest | https://github.com/imbas007/CVE-2025-49844-Vulnerability-Scanner | https://github.com/imbas007/CVE-2025-49844-Vulnerability-Scanner |
| trickest | https://github.com/jonatanjacobsson/ifcpipeline | https://github.com/jonatanjacobsson/ifcpipeline |
| trickest | https://github.com/marc-ko/daily-trending-repo | https://github.com/marc-ko/daily-trending-repo |
| trickest | https://github.com/pedrorichil/CVE-2025-49844 | https://github.com/pedrorichil/CVE-2025-49844 |
| trickest | https://github.com/tanjiti/sec_profile | https://github.com/tanjiti/sec_profile |
| trickest | https://github.com/thexnumb/thexwriteup | https://github.com/thexnumb/thexwriteup |
| trickest | https://github.com/vitoplantamura/HackerNewsRemovals | https://github.com/vitoplantamura/HackerNewsRemovals |
| trickest | https://github.com/w4zu/Debian_security | https://github.com/w4zu/Debian_security |

### CVE-2021-41773 — CRITICAL 9.8

*Matched on:* Apache httpd 2.4.49 @ web01.lab.local:80/tcp

A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

> **CISA KEV** — Apache HTTP Server Path Traversal Vulnerability (added 2021-11-03)

| Source | What | Link |
|---|---|---|
| poc-in-github | thehackersbrain/CVE-2021-41773 | https://github.com/thehackersbrain/CVE-2021-41773 |
| poc-in-github | theLSA/apache-httpd-path-traversal-checker | https://github.com/theLSA/apache-httpd-path-traversal-checker |
| poc-in-github | Hydragyrum/CVE-2021-41773-Playground | https://github.com/Hydragyrum/CVE-2021-41773-Playground |
| poc-in-github | blackn0te/Apache-HTTP-Server-2.4.49-2.4.50-Path-Traversal-Remote-Code-Execution | https://github.com/blackn0te/Apache-HTTP-Server-2.4.49-2.4.50-Path-Traversal-Remote-Code-Execution |
| poc-in-github | iosifache/ApacheRCEEssay | https://github.com/iosifache/ApacheRCEEssay |
| poc-in-github | wangfly-me/Apache_Penetration_Tool | https://github.com/wangfly-me/Apache_Penetration_Tool |
| poc-in-github | Soliux/CVE-2021-41773 | https://github.com/Soliux/CVE-2021-41773 |
| poc-in-github | mr-exo/CVE-2021-41773 | https://github.com/mr-exo/CVE-2021-41773 |
| poc-in-github | cloudbyteelias/CVE-2021-41773 | https://github.com/cloudbyteelias/CVE-2021-41773 |
| poc-in-github | ksanchezcld/httpd-2.4.49 | https://github.com/ksanchezcld/httpd-2.4.49 |
| poc-in-github | wvverez/CVE-2021-41773-PoC | https://github.com/wvverez/CVE-2021-41773-PoC |
| poc-in-github | nwclasantha/Apache_2.4.29_Exploit | https://github.com/nwclasantha/Apache_2.4.29_Exploit |
| poc-in-github | Zyx2440/Apache-HTTP-Server-2.4.50-RCE | https://github.com/Zyx2440/Apache-HTTP-Server-2.4.50-RCE |
| poc-in-github | belajarqywok/cve-2021-41773-msf | https://github.com/belajarqywok/cve-2021-41773-msf |
| poc-in-github | OfriOuzan/CVE-2021-41773_CVE-2021-42013_Exploits | https://github.com/OfriOuzan/CVE-2021-41773_CVE-2021-42013_Exploits |
| poc-in-github | aqiao-jashell/py-CVE-2021-41773 | https://github.com/aqiao-jashell/py-CVE-2021-41773 |
| poc-in-github | aqiao-jashell/CVE-2021-41773 | https://github.com/aqiao-jashell/CVE-2021-41773 |
| poc-in-github | CalfCrusher/Path-traversal-RCE-Apache-2.4.49-2.4.50-Exploit | https://github.com/CalfCrusher/Path-traversal-RCE-Apache-2.4.49-2.4.50-Exploit |
| poc-in-github | mauricelambert/CVE-2021-41773 | https://github.com/mauricelambert/CVE-2021-41773 |
| poc-in-github | vulf/CVE-2021-41773_42013 | https://github.com/vulf/CVE-2021-41773_42013 |
| exploitdb | Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE) | https://www.exploit-db.com/exploits/50383 |
| exploitdb | Apache HTTP Server 2.4.50 - Remote Code Execution (RCE) (3) | https://www.exploit-db.com/exploits/50512 |
| metasploit | Apache 2.4.49/2.4.50 Traversal RCE scanner | https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/http/apache_normalize_path.rb |
| metasploit | Apache 2.4.49/2.4.50 Traversal RCE | https://github.com/rapid7/metasploit-framework/blob/master/modules/exploit/multi/http/apache_normalize_path_rce.rb |
| nuclei | Apache 2.4.49 - Path Traversal and Remote Code Execution | https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves/2021/CVE-2021-41773.yaml |
| hackerone | Internet Bug Bounty — Path Traversal and Remote Code Execution in Apache HTTP Server 2.4.4 | https://hackerone.com/reports/1400238 |
| hackerone | Internet Bug Bounty — Path traversal and file disclosure vulnerability in Apache HTTP Serv | https://hackerone.com/reports/1394916 |
| vulhub | Vulhub lab: httpd/CVE-2021-41773 | https://github.com/vulhub/vulhub/blob/master/httpd/CVE-2021-41773/README.md |
| trickest | https://github.com/0day666/Vulnerability-verification | https://github.com/0day666/Vulnerability-verification |
| trickest | https://github.com/0e0w/GoHackTools | https://github.com/0e0w/GoHackTools |
| trickest | https://github.com/0x3n0/redeam | https://github.com/0x3n0/redeam |
| trickest | https://github.com/0x783kb/Security-operation-book | https://github.com/0x783kb/Security-operation-book |
| trickest | https://github.com/0xAlmighty/CVE-2021-41773-PoC | https://github.com/0xAlmighty/CVE-2021-41773-PoC |
| trickest | https://github.com/0xGabe/Apache-CVEs | https://github.com/0xGabe/Apache-CVEs |
| trickest | https://github.com/0xIceKing/dfcf_def_atk_2024 | https://github.com/0xIceKing/dfcf_def_atk_2024 |
| trickest | https://github.com/0xRar/CVE-2021-41773 | https://github.com/0xRar/CVE-2021-41773 |
| trickest | https://github.com/0xStrygwyr/OSCP-Guide | https://github.com/0xStrygwyr/OSCP-Guide |
| trickest | https://github.com/0xZipp0/OSCP | https://github.com/0xZipp0/OSCP |
| trickest | https://github.com/0xabdoulaye/CTFs-Journey | https://github.com/0xabdoulaye/CTFs-Journey |
| trickest | https://github.com/0xb0rn3/r3cond0g | https://github.com/0xb0rn3/r3cond0g |
| trickest | https://github.com/0xc4t/CVE-2021-41773 | https://github.com/0xc4t/CVE-2021-41773 |
| trickest | https://github.com/0xfke/500-free-TryHackMe-rooms | https://github.com/0xfke/500-free-TryHackMe-rooms |
| trickest | https://github.com/0xkarthi/Tryhackme-Roadmap | https://github.com/0xkarthi/Tryhackme-Roadmap |
| trickest | https://github.com/0xneobyte/TryHackMe-Learning-Path-From-Beginner-to-Expert | https://github.com/0xneobyte/TryHackMe-Learning-Path-From-Beginner-to-Expert |
| trickest | https://github.com/0xsyr0/OSCP | https://github.com/0xsyr0/OSCP |
| trickest | https://github.com/11x-singhamit/Port-Scanner-with-Vulnerability-Awareness | https://github.com/11x-singhamit/Port-Scanner-with-Vulnerability-Awareness |
| trickest | https://github.com/12345qwert123456/CVE-2021-41773 | https://github.com/12345qwert123456/CVE-2021-41773 |
| trickest | https://github.com/189569400/Meppo | https://github.com/189569400/Meppo |

### CVE-2021-42013 — CRITICAL 9.8

*Matched on:* Apache httpd 2.4.49 @ web01.lab.local:80/tcp

It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

> **CISA KEV** — Apache HTTP Server Path Traversal Vulnerability (added 2021-11-03)

| Source | What | Link |
|---|---|---|
| poc-in-github | tangxiaofeng7/CVE-2022-22947-Spring-Cloud-Gateway | https://github.com/tangxiaofeng7/CVE-2022-22947-Spring-Cloud-Gateway |
| poc-in-github | Vulnmachines/cve-2021-42013 | https://github.com/Vulnmachines/cve-2021-42013 |
| poc-in-github | asaotomo/CVE-2021-42013-Apache-RCE-Poc-Exp | https://github.com/asaotomo/CVE-2021-42013-Apache-RCE-Poc-Exp |
| poc-in-github | andrea-mattioli/apache-exploit-CVE-2021-42013 | https://github.com/andrea-mattioli/apache-exploit-CVE-2021-42013 |
| poc-in-github | walnutsecurity/cve-2021-42013 | https://github.com/walnutsecurity/cve-2021-42013 |
| poc-in-github | TheLastVvV/CVE-2021-42013_Reverse-Shell | https://github.com/TheLastVvV/CVE-2021-42013_Reverse-Shell |
| poc-in-github | TheLastVvV/CVE-2021-42013 | https://github.com/TheLastVvV/CVE-2021-42013 |
| poc-in-github | mauricelambert/CVE-2021-42013 | https://github.com/mauricelambert/CVE-2021-42013 |
| poc-in-github | jas9reet/CVE-2021-42013-LAB | https://github.com/jas9reet/CVE-2021-42013-LAB |
| poc-in-github | robotsense1337/CVE-2021-42013 | https://github.com/robotsense1337/CVE-2021-42013 |
| poc-in-github | CyberCTF/vulhub-httpd-cve-2021-42013 | https://github.com/CyberCTF/vulhub-httpd-cve-2021-42013 |
| poc-in-github | berraesen/apache-cve-2021-42013-lab | https://github.com/berraesen/apache-cve-2021-42013-lab |
| poc-in-github | lmcewen9/cve-2021-42013 | https://github.com/lmcewen9/cve-2021-42013 |
| poc-in-github | zeynepglygt/apache-cve-2021-42013-rce | https://github.com/zeynepglygt/apache-cve-2021-42013-rce |
| poc-in-github | drackyjr/CVE-2021-42013 | https://github.com/drackyjr/CVE-2021-42013 |
| poc-in-github | FakhriCRD/Apache-CVE-2021-42013-RCE-Exploit | https://github.com/FakhriCRD/Apache-CVE-2021-42013-RCE-Exploit |
| poc-in-github | Makavellik/POC-CVE-2021-42013-EXPLOIT | https://github.com/Makavellik/POC-CVE-2021-42013-EXPLOIT |
| poc-in-github | Jhonsonwannaa/cve-2021-42013-apache | https://github.com/Jhonsonwannaa/cve-2021-42013-apache |
| poc-in-github | rafifdna/CVE-2021-42013 | https://github.com/rafifdna/CVE-2021-42013 |
| poc-in-github | BassoNicolas/CVE-2021-42013 | https://github.com/BassoNicolas/CVE-2021-42013 |
| exploitdb | Apache HTTP Server 2.4.50 - Path Traversal & Remote Code Execution (RCE) | https://www.exploit-db.com/exploits/50406 |
| exploitdb | Apache HTTP Server 2.4.50 - Remote Code Execution (RCE) (2) | https://www.exploit-db.com/exploits/50446 |
| exploitdb | Apache HTTP Server 2.4.50 - Remote Code Execution (RCE) (3) | https://www.exploit-db.com/exploits/50512 |
| exploitdb | Apache HTTP Server 2.4.50 Path Traversal and Code Execution - Paper | https://www.exploit-db.com/exploits/50552 |
| metasploit | Apache 2.4.49/2.4.50 Traversal RCE scanner | https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/http/apache_normalize_path.rb |
| metasploit | Apache 2.4.49/2.4.50 Traversal RCE | https://github.com/rapid7/metasploit-framework/blob/master/modules/exploit/multi/http/apache_normalize_path_rce.rb |
| nuclei | Apache 2.4.49/2.4.50 - Path Traversal and Remote Code Execution | https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves/2021/CVE-2021-42013.yaml |
| hackerone | Internet Bug Bounty — Path Traversal and Remote Code Execution in Apache HTTP Server 2.4.4 | https://hackerone.com/reports/1400238 |
| vulhub | Vulhub lab: httpd/CVE-2021-42013 | https://github.com/vulhub/vulhub/blob/master/httpd/CVE-2021-42013/README.md |
| trickest | https://github.com/0day666/Vulnerability-verification | https://github.com/0day666/Vulnerability-verification |
| trickest | https://github.com/0x783kb/Security-operation-book | https://github.com/0x783kb/Security-operation-book |
| trickest | https://github.com/0xGabe/Apache-CVEs | https://github.com/0xGabe/Apache-CVEs |
| trickest | https://github.com/0xStrygwyr/OSCP-Guide | https://github.com/0xStrygwyr/OSCP-Guide |
| trickest | https://github.com/0xZipp0/OSCP | https://github.com/0xZipp0/OSCP |
| trickest | https://github.com/0xb0rn3/r3cond0g | https://github.com/0xb0rn3/r3cond0g |
| trickest | https://github.com/0xsyr0/OSCP | https://github.com/0xsyr0/OSCP |
| trickest | https://github.com/12345qwert123456/CVE-2021-42013 | https://github.com/12345qwert123456/CVE-2021-42013 |
| trickest | https://github.com/20142995/pocsuite3 | https://github.com/20142995/pocsuite3 |
| trickest | https://github.com/5gstudent/cve-2021-41773-and-cve-2021-42013 | https://github.com/5gstudent/cve-2021-41773-and-cve-2021-42013 |
| trickest | https://github.com/AMatheusFeitosaM/OSCP-Cheat | https://github.com/AMatheusFeitosaM/OSCP-Cheat |
| trickest | https://github.com/AMazkun/vuln-report-normalizer | https://github.com/AMazkun/vuln-report-normalizer |
| trickest | https://github.com/Adashz/CVE-2021-42013 | https://github.com/Adashz/CVE-2021-42013 |
| trickest | https://github.com/AhenKay/INPT_report | https://github.com/AhenKay/INPT_report |
| trickest | https://github.com/ArrestX/--POC | https://github.com/ArrestX/--POC |
| trickest | https://github.com/Awrrays/FrameVul | https://github.com/Awrrays/FrameVul |
| trickest | https://github.com/CHYbeta/Vuln100Topics | https://github.com/CHYbeta/Vuln100Topics |
| trickest | https://github.com/CHYbeta/Vuln100Topics20 | https://github.com/CHYbeta/Vuln100Topics20 |
| trickest | https://github.com/CLincat/vulcat | https://github.com/CLincat/vulcat |

### CVE-2021-44790 — CRITICAL 9.8

*Matched on:* Apache httpd 2.4.49 @ web01.lab.local:80/tcp

A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser (r:parsebody() called from Lua scripts). The Apache httpd team is not aware of an exploit for the vulnerabilty though it might be possible to craft one. This issue affects Apache HTTP Server 2.4.51 and earlier.

| Source | What | Link |
|---|---|---|
| poc-in-github | CerberusMrXi/Apache-Lua-Buffer-Overflow-Exploit-CVE-2021-44790 | https://github.com/CerberusMrXi/Apache-Lua-Buffer-Overflow-Exploit-CVE-2021-44790 |
| poc-in-github | nuPacaChi/-CVE-2021-44790 | https://github.com/nuPacaChi/-CVE-2021-44790 |
| exploitdb | Apache 2.4.x - Buffer Overflow | https://www.exploit-db.com/exploits/51193 |
| trickest | https://github.com/0xdc10/picklerick-thm | https://github.com/0xdc10/picklerick-thm |
| trickest | https://github.com/20142995/nuclei-templates | https://github.com/20142995/nuclei-templates |
| trickest | https://github.com/8ctorres/SIND-Practicas | https://github.com/8ctorres/SIND-Practicas |
| trickest | https://github.com/CpDant/PenTestingProject | https://github.com/CpDant/PenTestingProject |
| trickest | https://github.com/NeoOniX/5ATTACK | https://github.com/NeoOniX/5ATTACK |
| trickest | https://github.com/PierreChrd/py-projet-tut | https://github.com/PierreChrd/py-projet-tut |
| trickest | https://github.com/Samaritin/OSINT | https://github.com/Samaritin/OSINT |
| trickest | https://github.com/Totes5706/TotesHTB | https://github.com/Totes5706/TotesHTB |
| trickest | https://github.com/alpaykuzu/PortScanner-CVE-Tool | https://github.com/alpaykuzu/PortScanner-CVE-Tool |
| trickest | https://github.com/bioly230/THM_Skynet | https://github.com/bioly230/THM_Skynet |
| trickest | https://github.com/cretlaw/SnykDesk | https://github.com/cretlaw/SnykDesk |
| trickest | https://github.com/cyb3r-w0lf/nuclei-template-collection | https://github.com/cyb3r-w0lf/nuclei-template-collection |
| trickest | https://github.com/emotest1/emo_emo | https://github.com/emotest1/emo_emo |
| trickest | https://github.com/firatesatoglu/shodanSearch | https://github.com/firatesatoglu/shodanSearch |
| trickest | https://github.com/jkiala2/Projet_etude_M1 | https://github.com/jkiala2/Projet_etude_M1 |
| trickest | https://github.com/kasem545/vulnsearch | https://github.com/kasem545/vulnsearch |
| trickest | https://github.com/lekctut/sdb-hw-13-01 | https://github.com/lekctut/sdb-hw-13-01 |
| trickest | https://github.com/minektur/rhel8-cve-eratta-checker | https://github.com/minektur/rhel8-cve-eratta-checker |
| trickest | https://github.com/nullenc0de/vulnseer | https://github.com/nullenc0de/vulnseer |

### CVE-2023-38408 — CRITICAL 9.8

*Matched on:* OpenSSH 8.2p1 @ web01.lab.local:22/tcp

The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution if an agent is forwarded to an attacker-controlled system. (Code in /usr/lib is not necessarily safe for loading into ssh-agent.) NOTE: this issue exists because of an incomplete fix for CVE-2016-10009.

| Source | What | Link |
|---|---|---|
| poc-in-github | snowcra5h/CVE-2023-38408 | https://github.com/snowcra5h/CVE-2023-38408 |
| poc-in-github | Adel2411/cve-2023-38408 | https://github.com/Adel2411/cve-2023-38408 |
| poc-in-github | nonosticisiguzo-command/nmap-scan-results | https://github.com/nonosticisiguzo-command/nmap-scan-results |
| poc-in-github | TX-One/CVE-2023-38408 | https://github.com/TX-One/CVE-2023-38408 |
| poc-in-github | fazilbaig1/cve_2023_38408_scanner | https://github.com/fazilbaig1/cve_2023_38408_scanner |
| poc-in-github | mrtacojr/CVE-2023-38408 | https://github.com/mrtacojr/CVE-2023-38408 |
| poc-in-github | wxrdnx/CVE-2023-38408 | https://github.com/wxrdnx/CVE-2023-38408 |
| poc-in-github | classic130/CVE-2023-38408 | https://github.com/classic130/CVE-2023-38408 |
| poc-in-github | LucasPDiniz/CVE-2023-38408 | https://github.com/LucasPDiniz/CVE-2023-38408 |
| poc-in-github | kali-mx/CVE-2023-38408 | https://github.com/kali-mx/CVE-2023-38408 |
| trickest | https://github.com/0xfke/500-free-TryHackMe-rooms | https://github.com/0xfke/500-free-TryHackMe-rooms |
| trickest | https://github.com/0xor0ne/awesome-list | https://github.com/0xor0ne/awesome-list |
| trickest | https://github.com/5thphlame/Free-Rooms-TryHackMe | https://github.com/5thphlame/Free-Rooms-TryHackMe |
| trickest | https://github.com/ARESHAmohanad/THM | https://github.com/ARESHAmohanad/THM |
| trickest | https://github.com/ARESHAmohanad/tryhackme | https://github.com/ARESHAmohanad/tryhackme |
| trickest | https://github.com/Adel2411/cyber-combat | https://github.com/Adel2411/cyber-combat |
| trickest | https://github.com/Aijoo100/Aijoo100 | https://github.com/Aijoo100/Aijoo100 |
| trickest | https://github.com/AlienTec1908/Magifi_HackMyVM_Hard | https://github.com/AlienTec1908/Magifi_HackMyVM_Hard |
| trickest | https://github.com/ButchBytes-sec/TryHackMe | https://github.com/ButchBytes-sec/TryHackMe |
| trickest | https://github.com/Dh4v4l8/TRYHACKME-ROOMS | https://github.com/Dh4v4l8/TRYHACKME-ROOMS |
| trickest | https://github.com/FarelRA/MKM_ssh | https://github.com/FarelRA/MKM_ssh |
| trickest | https://github.com/FirikiIntelligence/Courses | https://github.com/FirikiIntelligence/Courses |
| trickest | https://github.com/Hunterdii/TryHackMe-Roadmap | https://github.com/Hunterdii/TryHackMe-Roadmap |
| trickest | https://github.com/Hunterdii/tryhackme-free-rooms | https://github.com/Hunterdii/tryhackme-free-rooms |
| trickest | https://github.com/Jalexander798/JA_Tools-Cybersecurity-Resource-2 | https://github.com/Jalexander798/JA_Tools-Cybersecurity-Resource-2 |
| trickest | https://github.com/LucasPDiniz/StudyRoom | https://github.com/LucasPDiniz/StudyRoom |
| trickest | https://github.com/Magisk-Modules-Repo/ssh | https://github.com/Magisk-Modules-Repo/ssh |
| trickest | https://github.com/Manjunath-Malagundla/itsecgames-assignment | https://github.com/Manjunath-Malagundla/itsecgames-assignment |

### CVE-2022-22720 — CRITICAL 9.8

*Matched on:* Apache httpd 2.4.49 @ web01.lab.local:80/tcp

Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered discarding the request body, exposing the server to HTTP Request Smuggling

| Source | What | Link |
|---|---|---|
| trickest | https://github.com/20142995/nuclei-templates | https://github.com/20142995/nuclei-templates |
| trickest | https://github.com/8ctorres/SIND-Practicas | https://github.com/8ctorres/SIND-Practicas |
| trickest | https://github.com/Benasin/CVE-2022-22720 | https://github.com/Benasin/CVE-2022-22720 |
| trickest | https://github.com/EzeTauil/Maquina-Upload | https://github.com/EzeTauil/Maquina-Upload |
| trickest | https://github.com/NeoOniX/5ATTACK | https://github.com/NeoOniX/5ATTACK |
| trickest | https://github.com/PierreChrd/py-projet-tut | https://github.com/PierreChrd/py-projet-tut |
| trickest | https://github.com/Samaritin/OSINT | https://github.com/Samaritin/OSINT |
| trickest | https://github.com/Totes5706/TotesHTB | https://github.com/Totes5706/TotesHTB |
| trickest | https://github.com/bioly230/THM_Skynet | https://github.com/bioly230/THM_Skynet |
| trickest | https://github.com/cyb3r-w0lf/nuclei-template-collection | https://github.com/cyb3r-w0lf/nuclei-template-collection |
| trickest | https://github.com/firatesatoglu/shodanSearch | https://github.com/firatesatoglu/shodanSearch |
| trickest | https://github.com/jkiala2/Projet_etude_M1 | https://github.com/jkiala2/Projet_etude_M1 |
| trickest | https://github.com/kasem545/vulnsearch | https://github.com/kasem545/vulnsearch |
| trickest | https://github.com/lekctut/sdb-hw-13-01 | https://github.com/lekctut/sdb-hw-13-01 |
| trickest | https://github.com/minektur/rhel8-cve-eratta-checker | https://github.com/minektur/rhel8-cve-eratta-checker |
| trickest | https://github.com/pedr0alencar/vlab-metasploitable2 | https://github.com/pedr0alencar/vlab-metasploitable2 |
| trickest | https://github.com/zxTyphoon/Pentest | https://github.com/zxTyphoon/Pentest |
| trickest | https://www.oracle.com/security-alerts/cpuapr2022.html | https://www.oracle.com/security-alerts/cpuapr2022.html |
| trickest | https://www.oracle.com/security-alerts/cpujul2022.html | https://www.oracle.com/security-alerts/cpujul2022.html |

### CVE-2026-60002 — CRITICAL 9.4

*Matched on:* OpenSSH 8.2p1 @ web01.lab.local:22/tcp

ssh in OpenSSH before 10.4 can have a use-after-free when a server changes its host key during a key re-exchange. (This outcome occurs only on the client side.)

_No public PoC found._

### CVE-2026-2332 — CRITICAL 9.1

*Matched on:* Jetty 9.4.43 @ 10.10.14.22:8080/tcp

In Eclipse Jetty, the HTTP/1.1 parser is vulnerable to request smuggling when chunk extensions are used, similar to the "funky chunks" techniques outlined here:
  *  https://w4ke.info/2025/06/18/funky-chunks.html

  *  https://w4ke.info/2025/10/29/funky-chunks-2.html


Jetty terminates chunk extension parsing at \r\n inside quoted strings instead of treating this as an error.




POST / HTTP/1.1
Host: localhost
Transfer-Encoding: chunked

1;ext="val
X
0

GET /smuggled HTTP/1.1
...





Note how the chunk extension does not close the double quotes, and it is able to inject a smuggled request.

| Source | What | Link |
|---|---|---|
| poc-in-github | xiaoqiMikko/jetty-line-check | https://github.com/xiaoqiMikko/jetty-line-check |
| trickest | https://w4ke.info/2025/06/18/funky-chunks.html | https://w4ke.info/2025/06/18/funky-chunks.html |
| trickest | https://w4ke.info/2025/10/29/funky-chunks-2.htmlJetty | https://w4ke.info/2025/10/29/funky-chunks-2.html |
| trickest | https://github.com/jetty/jetty.project/security/advisories/GHSA-355h-qmc2-wpwf | https://github.com/jetty/jetty.project/security/advisories/GHSA-355h-qmc2-wpwf |

### CVE-2022-24834 — HIGH 8.8

*Matched on:* Redis key-value store 6.0.9 @ 10.10.14.22:6379/tcp

Redis is an in-memory database that persists on disk. A specially crafted Lua script executing in Redis can trigger a heap overflow in the cjson library, and result with heap corruption and potentially remote code execution. The problem exists in all versions of Redis with Lua scripting support, starting from 2.6, and affects only authenticated and authorized users. The problem is fixed in versions 7.0.12, 6.2.13, and 6.0.20.

| Source | What | Link |
|---|---|---|
| trickest | https://github.com/0xor0ne/awesome-list | https://github.com/0xor0ne/awesome-list |
| trickest | https://github.com/DukeSec97/CVE-2022-24834- | https://github.com/DukeSec97/CVE-2022-24834- |
| trickest | https://github.com/Jalexander798/JA_Tools-Cybersecurity-Resource-2 | https://github.com/Jalexander798/JA_Tools-Cybersecurity-Resource-2 |
| trickest | https://github.com/P3gEcTH8uJiYFVKb7lIn/awesome-list | https://github.com/P3gEcTH8uJiYFVKb7lIn/awesome-list |
| trickest | https://github.com/PsychoPunkSage/Chronark | https://github.com/PsychoPunkSage/Chronark |
| trickest | https://github.com/bachkhoasoft/awesome-list-ks | https://github.com/bachkhoasoft/awesome-list-ks |
| trickest | https://github.com/convisolabs/CVE-2022-24834 | https://github.com/convisolabs/CVE-2022-24834 |
| trickest | https://github.com/gglessner/redisClient | https://github.com/gglessner/redisClient |
| trickest | https://github.com/kolaarionvull/awesome-list | https://github.com/kolaarionvull/awesome-list |
| trickest | https://github.com/plzheheplztrying/cve_monitor | https://github.com/plzheheplztrying/cve_monitor |

### CVE-2021-32626 — HIGH 8.8

*Matched on:* Redis key-value store 6.0.9 @ 10.10.14.22:6379/tcp

Redis is an open source, in-memory database that persists on disk. In affected versions specially crafted Lua scripts executing in Redis can cause the heap-based Lua stack to be overflowed, due to incomplete checks for this condition. This can result with heap corruption and potentially remote code execution. This problem exists in all versions of Redis with Lua scripting support, starting from 2.6. The problem is fixed in versions 6.2.6, 6.0.16 and 5.0.14. For users unable to update an additional workaround to mitigate the problem without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

| Source | What | Link |
|---|---|---|
| trickest | https://github.com/gglessner/redisClient | https://github.com/gglessner/redisClient |
| trickest | https://github.com/jiuxi-tech/cybersec | https://github.com/jiuxi-tech/cybersec |
| trickest | https://www.oracle.com/security-alerts/cpuapr2022.html | https://www.oracle.com/security-alerts/cpuapr2022.html |

### CVE-2021-32762 — HIGH 8.8

*Matched on:* Redis key-value store 6.0.9 @ 10.10.14.22:6379/tcp

Redis is an open source, in-memory database that persists on disk. The redis-cli command line tool and redis-sentinel service may be vulnerable to integer overflow when parsing specially crafted large multi-bulk network replies. This is a result of a vulnerability in the underlying hiredis library which does not perform an overflow check before calling the calloc() heap allocation function. This issue only impacts systems with heap allocators that do not perform their own overflow checks. Most modern systems do and are therefore not likely to be affected. Furthermore, by default redis-sentinel uses the jemalloc allocator which is also not vulnerable. The problem is fixed in Redis versions 6.

| Source | What | Link |
|---|---|---|
| trickest | https://www.oracle.com/security-alerts/cpuapr2022.html | https://www.oracle.com/security-alerts/cpuapr2022.html |

### CVE-2026-10050 — HIGH 8.7

*Matched on:* Jetty 9.4.43 @ 10.10.14.22:8080/tcp

In Eclipse Jetty, the Digest authentication server-side component uses ISO-8859-1 to encode the password as bytes.



This was done because the initial specification for HTTP did not specify explicitly a charset, and it was assumed to be ISO-8859-1 for historical reasons.



If the password contains characters that cannot be represented in ISO-8859-1, they are silently replaced by `?`. This happens with passwords that contain Chinese, Cyrillic or Greek characters, for example: `αβ123` converts to `??123`.



An attacker can send a request with a digest `Authorization` header crafted with a password made of only `?` characters; the server would match any password of the same length that conta

| Source | What | Link |
|---|---|---|
| trickest | RFC-7616 | https://datatracker.ietf.org/doc/html/rfc7616 |
| trickest | https://github.com/jetty/jetty.project/security/advisories/GHSA-2fvj-hgj9-j2gr | https://github.com/jetty/jetty.project/security/advisories/GHSA-2fvj-hgj9-j2gr |

### CVE-2026-35385 — HIGH 8.1

*Matched on:* OpenSSH 8.2p1 @ web01.lab.local:22/tcp

In OpenSSH before 10.3, a file downloaded by scp may be installed setuid or setgid, an outcome contrary to some users' expectations, if the download is performed as root with -O (legacy scp protocol) and without -p (preserve mode).

_No public PoC found._

### CVE-2026-35414 — HIGH 8.1

*Matched on:* OpenSSH 8.2p1 @ web01.lab.local:22/tcp

OpenSSH before 10.3 mishandles the authorized_keys principals option in uncommon scenarios involving a principals list in conjunction with a Certificate Authority that makes certain use of comma characters.

| Source | What | Link |
|---|---|---|
| poc-in-github | killercd/CVE-2026-35414 | https://github.com/killercd/CVE-2026-35414 |

### CVE-2025-5115 — HIGH 7.7

*Matched on:* Jetty 9.4.43 @ 10.10.14.22:8080/tcp

In Eclipse Jetty, versions <=9.4.57, <=10.0.25, <=11.0.25, <=12.0.21, <=12.1.0.alpha2, an HTTP/2 client may trigger the server to send RST_STREAM frames, for example by sending frames that are malformed or that should not be sent in a particular stream state, therefore forcing the server to consume resources such as CPU and memory.


For example, a client can open a stream and then send WINDOW_UPDATE frames with window size increment of 0, which is illegal.
Per specification  https://www.rfc-editor.org/rfc/rfc9113.html#name-window_update , the server should send a RST_STREAM frame.
The client can now open another stream and send another bad WINDOW_UPDATE, therefore causing the server to cons

| Source | What | Link |
|---|---|---|
| trickest | https://github.com/w4zu/Debian_security | https://github.com/w4zu/Debian_security |
| trickest | https://www.rfc-editor.org/rfc/rfc9113.html#name-window_update | https://www.rfc-editor.org/rfc/rfc9113.html#name-window_update |
| trickest | https://github.com/jetty/jetty.project/security/advisories/GHSA-mmxm-8w33-wc4h | https://github.com/jetty/jetty.project/security/advisories/GHSA-mmxm-8w33-wc4h |

### CVE-2022-2048 — HIGH 7.5

*Matched on:* Jetty 9.4.43 @ 10.10.14.22:8080/tcp

In Eclipse Jetty HTTP/2 server implementation, when encountering an invalid HTTP/2 request, the error handling has a bug that can wind up not properly cleaning up the active connections and associated resources. This can lead to a Denial of Service scenario where there are no enough resources left to process good requests.

| Source | What | Link |
|---|---|---|
| trickest | https://github.com/m3n0sd0n4ld/uCVE | https://github.com/m3n0sd0n4ld/uCVE |
| trickest | https://github.com/pastelvacatio/uCVE | https://github.com/pastelvacatio/uCVE |

### CVE-2023-21980 — HIGH 7.1

*Matched on:* MySQL 5.7.31 @ web01.lab.local:3306/tcp

Vulnerability in the MySQL Server product of Oracle MySQL (component: Client programs).  Supported versions that are affected are 5.7.41 and prior and  8.0.32 and prior. Difficult to exploit vulnerability allows low privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in takeover of MySQL Server. CVSS 3.1 Base Score 7.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H).

| Source | What | Link |
|---|---|---|
| trickest | https://www.oracle.com/security-alerts/cpuapr2023.html | https://www.oracle.com/security-alerts/cpuapr2023.html |

### CVE-2020-14765 — MEDIUM 6.5

*Matched on:* MySQL 5.7.31 @ web01.lab.local:3306/tcp

Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: FTS). Supported versions that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).

| Source | What | Link |
|---|---|---|
| trickest | https://github.com/AhenKay/INPT_report | https://github.com/AhenKay/INPT_report |
| trickest | https://github.com/Dorsaa-Francis/inpt_report | https://github.com/Dorsaa-Francis/inpt_report |
| trickest | https://github.com/Farrhouq/Inpt-report | https://github.com/Farrhouq/Inpt-report |
| trickest | https://github.com/Samue290/INPT-REPORT | https://github.com/Samue290/INPT-REPORT |
| trickest | https://github.com/adugyeni/INPT_Report | https://github.com/adugyeni/INPT_Report |
| trickest | https://github.com/israelbarnabas/inpt-report | https://github.com/israelbarnabas/inpt-report |
| trickest | https://github.com/lukaspustina/cve-scorer | https://github.com/lukaspustina/cve-scorer |
| trickest | https://www.oracle.com/security-alerts/cpuoct2020.html | https://www.oracle.com/security-alerts/cpuoct2020.html |

### CVE-2020-14769 — MEDIUM 6.5

*Matched on:* MySQL 5.7.31 @ web01.lab.local:3306/tcp

Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).

| Source | What | Link |
|---|---|---|
| trickest | https://github.com/AhenKay/INPT_report | https://github.com/AhenKay/INPT_report |
| trickest | https://github.com/Dorsaa-Francis/inpt_report | https://github.com/Dorsaa-Francis/inpt_report |
| trickest | https://github.com/Farrhouq/Inpt-report | https://github.com/Farrhouq/Inpt-report |
| trickest | https://github.com/Samue290/INPT-REPORT | https://github.com/Samue290/INPT-REPORT |
| trickest | https://github.com/adugyeni/INPT_Report | https://github.com/adugyeni/INPT_Report |
| trickest | https://github.com/israelbarnabas/inpt-report | https://github.com/israelbarnabas/inpt-report |
| trickest | https://github.com/lukaspustina/cve-scorer | https://github.com/lukaspustina/cve-scorer |
| trickest | https://www.oracle.com/security-alerts/cpuoct2020.html | https://www.oracle.com/security-alerts/cpuoct2020.html |

### CVE-2020-14775 — MEDIUM 6.5

*Matched on:* MySQL 5.7.31 @ web01.lab.local:3306/tcp

Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are affected are 5.7.31 and prior and 8.0.21 and prior. Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).

| Source | What | Link |
|---|---|---|
| trickest | https://github.com/lukaspustina/cve-scorer | https://github.com/lukaspustina/cve-scorer |
| trickest | https://www.oracle.com/security-alerts/cpuoct2020.html | https://www.oracle.com/security-alerts/cpuoct2020.html |
