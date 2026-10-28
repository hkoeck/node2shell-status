# Changelog

Newest entry first.

## Update 3 – 28 Oct 2026, 14:18 UTC

Section 2 rebuilt as **"IPS / WAF protection"**: network IPS / NGFW, WAF / CDN, and scanners / runtime detection, plus a short note on what IPS / WAF can and cannot cover. Other sections were not re-checked.

- **Palo Alto:** the advisory named Threat ID **97686** (content 9165+) as partial coverage on 26–27 Oct. The text was removed on 28 Oct 06:55 UTC, so there is no current Threat ID. The old text is taken from a Wayback snapshot of 27 Oct 21:07 UTC.
- **Cisco / Talos:** no Snort rule in the Talos rule releases of 20, 21 and 27 Oct or in the Snort 3 community rules. The Cisco advisory names no SIDs.
- **Fortinet:** IPS signature **62703**, per Threat Signal 6556 (26 Oct). The encyclopedia entry is behind bot protection, so its details are not verified.
- **Azure WAF:** DRS 2.2 rule 920450 protects by default; a custom rule covers older rule sets.
- **Akamai:** status-page incident "investigating"; WAF coverage not verified.
- **Check Point:** CPAI-2026-15802 confirmed as its only protection for this CVE.
- **Nothing found:** Suricata ET Open, AWS WAF managed rules, OWASP CRS.
- **Could not check:** Juniper IDP, Sophos, SonicWall, WatchGuard signature lists, PAN Threat Vault.

## Update 2 – 28 Oct 2026, 10:30 UTC

Coverage widened. The README went from about 1,800 to about 2,900 words, with the same structure as the PHP2Shell page. Details: [VERIFICATION.md](VERIFICATION.md#update-2-checks-28-oct-2026).

- **New sections:**
  - WAF, IPS and detection content: Cloudflare, Fastly, Imperva, Vercel, F5, Check Point, Trend Micro TippingPoint, Tenable, Qualys.
  - Cloud platforms and container images: Azure, AWS, Google Cloud, Vercel, Docker `node`, Red Hat images.
  - Government / CERT: CISA, BSI, CSA Singapore, CERT-FR; checked with nothing found: CERT-EU, CCCS, NCSC-UK.
  - "Checking whether you are patched", "Fork it" and "Sources".
- **New appliance rows:**
  - HPE alert (27 Oct, no products named yet) and Trend Micro (assessment ongoing, TippingPoint 48101).
  - **Citrix, now checked:** the support search runs inside an iframe, so update 1 saw an empty page. The search API read in the browser finds no article for this CVE.
  - "Checked, nothing found": Sophos, SonicWall, Juniper, Ivanti, WatchGuard, Barracuda, Nutanix, Splunk, A10, Siemens, Zscaler blog.
  - "Could not check" row: Broadcom / VMware, NetApp, Akamai, Arista, Extreme, Infoblox, Forcepoint, Trellix, Netskope, Gigamon.
- **Microsoft (MSRC):**
  - Critical for .NET / Visual Studio, CVSS 8.1, exploited "No".
  - .NET SDK versions; Visual Studio 2019 / 2022 / 2026 and PowerShell 7.4–7.6 fixed versions.
  - Azure Linux 3.0 fixed.
- **Distributions added:** Azure Linux 3.0, Photon OS 5, Alpine 3.22, CloudLinux / TuxCare (`alt-nodejs` bundles its own Brotli). CIQ Rocky 9.2 LTS is listed only as a Tenable lead.
- **Exploitation:**
  - CISA alert wording "based on evidence of active exploitation".
  - BSI "Exploit aufgenommen" (27 Oct).
  - Tenable: has not independently confirmed the ELLIO activity.
  - Previdian honeypot hit, reported only by The Hacker News, marked not verified.
- **Not verified, not used as fact:** a news report of a VMware SDDC Manager advisory for this CVE. Broadcom notification 38017, which search results linked to it, is an unrelated August advisory.
- **Re-read, unchanged:** all 67 update-1 curl sources (10:20–10:29 UTC), Rocky Apollo, Sophos RSS, the SonicWall API and both F5 articles (10:29–10:30 UTC). Only wording changes, and changes in secondary sources (Rapid7, Help Net Security now mention KEV). The Juniper and Ivanti portal searches were not repeated.
- **Control test for "nothing found" rows:** a vendor list only counts if it also shows that vendor's PHP2Shell item. Zscaler failed this test and moved to "could not check".

## Correction – 28 Oct 2026, 09:53 UTC

- VERIFICATION.md: check-time ranges ending in 09:47 replaced by ranges between printed `date -u` anchors (no command printed 09:47).
- SUSE severity: SUSE gives CVSS 3.1 8.1 but no "Important" rating on its page; Key facts corrected.
- Node.js `process.versions.brotli`: confirmed in the v24.22.1 source tree (bundled `version.h` still says 1.2.0, decoder already patched).
- Oracle Linux wording below made precise; Ruby gem bullet moved out of "Corrected" (the draft already had 0.9.1).

## Update 1 – 28 Oct 2026, 09:46 UTC

First version. Built from a user-supplied draft (PDF), with every row re-checked at the primary source (details in [VERIFICATION.md](VERIFICATION.md)). Differences from the draft:

- **Timestamp:** the draft said "approx. 10:30 UTC" but was created at 09:24 UTC. This version uses the real check times (09:36–09:46 UTC).
- **Out of scope (enterprise only), dropped:** Fedora, openSUSE Tumbleweed, Debian forky / sid, the EPEL "not applicable" row.
- **Added:** Oracle Linux, which lists Node.js ELSAs for OL8 / 9 / 10 under this CVE while Red Hat has no Node.js RHSA yet. Amazon Linux. Freexian ELTS fixes for Debian 11 bullseye and 10 buster: the draft said bullseye was not listed. Red Hat EUS / AUS / E4S RHSAs and **.NET 8.0 affected on RHEL 8 / 9 / 10** (bundled copy). Envoy `1.36.12`. PHP Windows builds. The Cisco sentence that unlisted products are not affected.
- **Exploitation:** added CISA SSVC "active" (23 Oct), KEV forensic triage "No", ELLIO's in-the-wild report with its link, and ELLIO's x86-64 reproduction. Also noted that Red Hat's text still says there is no public, reliable RCE PoC.
- **Corrected:**
  - **Node.js check:** the draft recommended `node -p process.versions.brotli`. ELLIO reports it shows 1.2.0 on patched builds too, so the README now says to check `node --version`.
  - **Fortinet:** the CVE itself is listed as "high". 9.8 / Critical is the rating of the whole advisory.
  - **SUSE:** only SLE Micro 5.4 / 5.5 are in QA; Micro 6.0–6.2 and SLES 16.x are "In progress". openSUSE Leap 16.0 and SLE Micro 5.3 are affected without a fix.
- **F5:** both K-articles were read in a headless browser. All products except NGINX Plus / NGINX Open Source (not vulnerable) are still being researched. The draft's claim that BIG-IP iControl REST runs on Node.js was an inference and was removed.
- **Remi:** the draft inferred the system-library build from SRPM size. That is now verified from the spec file, which builds with system libbrotli and removes the bundled copy.
- **Vendors with no statement:** each row now says where it was checked: Sophos RSS, the SonicWall PSIRT API, Juniper and Ivanti portal search. Citrix, the Check Point KB and Akamai could not be checked.
- **Confirmed from the draft:** Ruby brotli gem 0.9.1 (maintainer comment), PAN-OS hotfix list, Debian / Ubuntu / RHEL brotli versions.
- **Not verified (secondary source):** the broccoli2shell.com list of unfixed bundled copies (DuckDB, Arrow, 7-Zip-zstd, p7zip, EDK II, v8-jsi) is listed only under Known gaps.
