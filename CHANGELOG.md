# Changelog

Newest entry first.

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
