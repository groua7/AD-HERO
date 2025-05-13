
# Active Directory for Cybersecurity Analysts: 15 Practical Skills to Learn

Welcome to this guide! As a Cybersecurity Analyst, understanding **Active Directory (AD)** is crucial for detecting threats, securing environments, and responding to incidents.

This README showcases 15 hands-on AD tasks, complete with explanations and examples to get you started.

---

## Table of Contents

1. [Create Users in Active Directory](#1-create-users-in-active-directory)
2. [Create and Manage Groups](#2-create-and-manage-groups)
3. [Enumerate AD Users and Groups](#3-enumerate-ad-users-and-groups)
4. [Audit Logon Events](#4-audit-logon-events)
5. [Check for Privileged Accounts](#5-check-for-privileged-accounts)
6. [Detect Inactive or Expired Accounts](#6-detect-inactive-or-expired-accounts)
7. [Enforce Password Policy and Detect Violations](#7-enforce-password-policy-and-detect-violations)
8. [Analyze Group Policy Objects (GPOs)](#8-analyze-group-policy-objects-gpos)
9. [Monitor AD Changes (Audit AD Events)](#9-monitor-ad-changes-audit-ad-events)
10. [Use BloodHound for AD Attack Path Mapping](#10-use-bloodhound-for-ad-attack-path-mapping)
11. [Perform LDAP Queries](#11-perform-ldap-queries)
12. [Check for Kerberoasting Vulnerabilities](#12-check-for-kerberoasting-vulnerabilities)
13. [Identify Delegated Permissions](#13-identify-delegated-permissions)
14. [Detect Golden Ticket Attacks](#14-detect-golden-ticket-attacks)
15. [Use AD Security Baseline Tools](#15-use-ad-security-baseline-tools)

---

## 1. Create Users in Active Directory

Use PowerShell to create a user in AD:

```powershell
New-ADUser -Name "John Smith" -SamAccountName jsmith -UserPrincipalName jsmith@domain.local -AccountPassword (ConvertTo-SecureString "P@ssword123" -AsPlainText -Force) -Enabled $true -Path "OU=Users,DC=domain,DC=local"

Best practice: place users in Organizational Units (OUs) for better control.

⸻

2. Create and Manage Groups

Create a group and add users:

# Create a group
New-ADGroup -Name "ITAdmins" -GroupScope Global -Path "OU=Groups,DC=domain,DC=local"

# Add user to group
Add-ADGroupMember -Identity "ITAdmins" -Members jsmith

Use groups to assign permissions instead of assigning them directly to users.

⸻

3. Enumerate AD Users and Groups

# List all users
Get-ADUser -Filter * | Select Name, SamAccountName

# List all groups
Get-ADGroup -Filter * | Select Name

Useful for account auditing and privilege reviews.

⸻

4. Audit Logon Events

Monitor successful and failed logons:

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Format-Table TimeCreated, Message -AutoSize

 • 4624 = Successful logon
 • 4625 = Failed logon

Helps detect brute-force attacks or unauthorized access.

⸻

5. Check for Privileged Accounts

List Domain Admins:

Get-ADGroupMember "Domain Admins"

Alert on unnecessary privileged accounts.

⸻

6. Detect Inactive or Expired Accounts

# Inactive > 90 days
Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly

# Expired accounts
Search-ADAccount -AccountExpired

Clean up or disable these accounts to reduce risk.

⸻

7. Enforce Password Policy and Detect Violations

# Find accounts with non-expiring passwords
Get-ADUser -Filter * -Properties PasswordNeverExpires | Where-Object {$_.PasswordNeverExpires -eq $true}

Check domain password policies via secpol.msc or Group Policy.

⸻

8. Analyze Group Policy Objects (GPOs)

# View all GPOs
Get-GPO -All

# Export GPO to HTML report
Get-GPOReport -Name "Default Domain Policy" -ReportType HTML -Path "C:\GPOReport.html"

Identify policies affecting passwords, logon restrictions, auditing, etc.

⸻

9. Monitor AD Changes (Audit AD Events)

Enable Audit Directory Service Changes in Group Policy.
 • Event ID 5136 = Object modified
 • Event ID 4720 = User account created
 • Event ID 4726 = User account deleted

Use Event Viewer or SIEM (e.g., Splunk, QRadar).

⸻

10. Use BloodHound for AD Attack Path Mapping
 • Download: https://github.com/BloodHoundAD/BloodHound
 • Run SharpHound to collect data:

SharpHound.exe -c All

Analyze paths to Domain Admins and privilege escalations.

⸻

11. Perform LDAP Queries

# Basic LDAP search
([adsisearcher]"(objectClass=user)").FindAll()

Understand how attackers and tools enumerate AD objects.

⸻

12. Check for Kerberoasting Vulnerabilities

Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select Name, ServicePrincipalName

Ensure strong passwords for service accounts with SPNs.

⸻

13. Identify Delegated Permissions

Check which users/groups have delegated permissions:

Get-ACL "AD:\OU=Users,DC=domain,DC=local" | Format-List

Detect excessive privileges that can be exploited.

⸻

14. Detect Golden Ticket Attacks

Golden Ticket attacks involve forging TGTs.
 • Monitor for:
 • Logon attempts with non-existent users
 • Event ID 4769 with unusual source IPs
 • High Kerberos ticket lifetimes

Tools like Mimikatz can simulate this—use lab only!

⸻

15. Use AD Security Baseline Tools
 • Microsoft Security Compliance Toolkit: Download (https://learn.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10)
 • Use PingCastle for AD Health & Risk Assessment: https://github.com/vletoux/pingcastle

PingCastle.exe --healthcheck --server domain.local

Get a full AD security risk report with remediation tips.

⸻

Final Lab Setup Suggestion

You can test these skills in:
 • VirtualBox/VMware + Windows Server 2019/2022 (with AD DS role)
 • Azure AD + Free Microsoft 365 Developer Account
 • TryHackMe (https://tryhackme.com/) labs: “Attacktive Directory,” “Blue Team AD,” etc.

⸻

Resources
 • Microsoft Learn: Active Directory (https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/)
 • BloodHound Documentation (https://bloodhound.readthedocs.io/)
 • Cyber Defender’s AD Checklist (https://github.com/trimstray/the-practical-guide-to-AD)

⸻

Secure the Kingdom — Master Active Directory!

