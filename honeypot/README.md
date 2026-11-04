# Cowrie honeypot on AWS

A Cowrie SSH and Telnet honeypot on EC2. It's the data source for this repo's SIEM work: every command it captures is known-malicious, so the logs work as a labelled dataset for parsing, MITRE ATT&CK mapping and writing detection rules.

## Architecture

```
Internet ──► :22 / :23 (security group) ──► nftables redirect ──► Cowrie :2222 / :2323 (user: cowrie)
                                                                     │
                       cowrie.json ──► CloudWatch agent ──► CloudWatch Logs  /honeypot/cowrie
                       rotated logs, tty recordings, malware ──► hourly timer ──► S3 archive bucket

Admin ──► AWS sign-in + MFA ──► SSM Session Manager (no inbound admin port, real sshd masked)
```

| Control | Choice |
|---|---|
| Network | Dedicated VPC (10.42.0.0/24) with no peering. The security group allows inbound 22 and 23 only, and outbound 80 and 443 only. |
| Admin access | SSM Session Manager. The real `sshd` is disabled and masked. |
| Process isolation | Cowrie runs as an unprivileged `cowrie` user in a Python venv, under a hardened systemd unit (`ProtectSystem=strict`, `NoNewPrivileges`, no capabilities). |
| Instance | Graviton t4g.small, Ubuntu 24.04, IMDSv2 required with hop limit 1, encrypted gp3 volume |
| IAM | `AmazonSSMManagedInstanceCore`, plus write-only access to the instance's own log group and archive bucket |
| Data durability | The log group and bucket have `DeletionPolicy: Retain`, so the dataset outlives the stack. |
| Cost guardrail | AWS Budget with email alerts |

### Reject-first-login

```ini
auth_class = AuthRandom
auth_class_parameters = 2, 2, 0
```

Each new source IP has its first login rejected and its second distinct credential pair accepted. A server that accepts the very first password it's offered looks like a honeypot. Setting `maxcache = 0` stops a credential pair that already worked from letting a new IP in on its first attempt.

## Deploy

```bash
aws cloudformation deploy \
  --region eu-west-2 \
  --stack-name cowrie-honeypot \
  --template-file honeypot/infra/honeypot.yaml \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides AlertEmail=you@example.com
```

Bootstrap takes about 5–10 minutes after the stack completes. To check on it:

```bash
aws ssm start-session --target <InstanceId> --region eu-west-2
sudo tail -n 50 /var/log/honeypot-bootstrap.log     # ends with HONEYPOT BOOTSTRAP COMPLETE
sudo systemctl status cowrie
sudo tail -f /opt/cowrie/var/log/cowrie/cowrie.json
```

## Tear down

```bash
aws cloudformation delete-stack --stack-name cowrie-honeypot --region eu-west-2
```

The S3 bucket and log group are retained on purpose. Delete them by hand once the data has been exported.

## Caveats

- Cowrie really fetches the URLs that attackers `wget` or `curl`, so the instance makes outbound connections to malware hosts. GuardDuty findings are expected.
- Malware samples are stored but never executed. Don't download them onto a workstation.
