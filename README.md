
# SOC Investigation Report – RDP Compromise

**Report ID:** INC-2025-1120-AZUKI  
**Analyst:** Pedro Fernandes Parreira  
**Date:** 22-November-2025  

## Summary
An attacker gained unauthorized RDP access to AZUKI-SL using admin credentials.
The attacker executed tools, established persistence, and stole sensitive business data.

## Findings
- Host compromised: AZUKI-SL
- Account: Administrator
- Method: RDP brute-force / credential reuse
- Persistence via registry
- Exfiltration over HTTPS

## Recommendations
- Implement MFA
- Close exposed RDP
- Harden PowerShell policies
- Strengthen monitoring

## Status
Complete
