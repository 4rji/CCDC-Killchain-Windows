# CCDC Kill Chains and Enumeration

This repository stores host enumeration notes and kill chain documentation for the CCDC lab. Add discovered services, validated findings, attack paths, evidence, and remediation notes here.

## Structure

- `enumeration/`: one file per host for inventory, services, and findings.
- `kill-chains/`: one file per host for documenting a validated sequence of actions and results.
- `evidence/`: supporting screenshots, logs, and command output, organized by host.

The included files are examples to complete during the exercise. Supplied inventory is recorded below; services and attack paths have not been verified.

## Hosts

| Host | Platform / role | LAN | Public address pattern |
| --- | --- | --- | --- |
| [Windows 11 Wks](enumeration/windows-11-wks.md) | Windows 11 · Blue-team workstation | `DHCP` | `172.31.20+team#.2` |
| [2019 MSSQL](enumeration/2019-mssql.md) | Server 2019 Std | `172.20.240.120` | `172.25.20+team#.120` |
| [2022 AD](enumeration/2022-ad.md) | Server 2022 Std · Identity & name services | `172.20.240.100` | `172.25.20+team#.100` |

Public addresses retain the supplied notation: `20+team#` means 20 plus the team number in the third octet. For example, team 1 uses `172.25.21.120` for 2019 MSSQL. Confirm the assigned team number before using an address.

## Lab access

The supplied lab credentials for all three hosts are `sysadmin / Changeme1!`. Console links were not provided.

## Workflow

1. Update the host enumeration file with timestamps, commands, and observed results.
2. Document confirmed action sequences in the matching kill chain file. Keep hypotheses clearly marked.
3. Save supporting evidence under `evidence/<host>/` and link it from the notes.
4. Record impact, remediation, and retest results. Perform actions only within the authorized exercise scope.

Do not commit additional passwords, private keys, or sensitive session data in evidence.
