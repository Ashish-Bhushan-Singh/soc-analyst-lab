Linux Multi-Stage Compromise Investigation

Training scenario — simulated logs and evidence for practice, not a real incident

Scenario

Investigated a simulated multi-stage compromise on webserver02, combining SSH brute-force activity, cron-based persistence, and a suspicious SUID binary as part of a SOC training exercise.

Analysis
Step 1 — SSH Brute-Force

The activity is very likely a real brute-force attack rather than normal testing.

There are more than 180 failed SSH attempts in approximately three minutes, coming from the same external IP address at roughly one attempt per second. The activity then resulted in a successful authentication to the admin account.

The combination of high-frequency authentication attempts and a confirmed successful login strongly supports malicious brute-force activity.

Evidence: evidence/SSH Authentication Log.txt

Step 2 — Cron Persistence

The cron entry runs every minute.

It silently downloads x.sh from the external IP address using curl and immediately pipes the downloaded content into Bash for execution.

This effectively gives the remote party recurring code execution on the server.

An attacker would likely add this after gaining access as a persistence mechanism. Even if the original SSH session ends, the cron job continues executing the attacker's code every minute.

Evidence: evidence/Cron Check.txt

Step 3 — SUID Binary Investigation

The newly discovered /opt/backup-tool/backup-agent is notable because it is owned by root and has the SUID bit set.

However, I would not immediately classify it as malicious simply because it is an unfamiliar SUID binary. Custom SUID-root programs can be legitimate company tools, particularly for administrative or backup functions.

Before deciding whether it is dangerous, I would check:

Who created or installed the file and when.
Ownership, permissions, and timestamps.
What type of file it is using file.
Its cryptographic hash.
Whether it is an approved company application.
Whether it appeared around the same time as the suspected compromise.
Whether its functionality could allow privilege escalation or command execution.

The timing is particularly important. If the binary appeared shortly after the successful SSH login, that would increase suspicion.

Evidence: evidence/SUID Find Output.txt

Timeline

The evidence supports the following possible attack chain:

Brute force → successful SSH login → persistence → possible privilege escalation

An attacker appears to have brute-forced the admin SSH account from 91.240.118.30 and successfully authenticated. After gaining access, they established persistence through a cron job that downloads and executes an attacker-controlled script every minute. A newly added SUID-root backup-agent was also discovered and may represent a privilege-escalation mechanism or backdoor, although this requires further investigation before being classified as malicious.

Disposition

Escalate immediately.

This is more than an isolated failed-login alert. Four findings support escalation:

High-volume SSH brute-force activity from an external IP.
Successful authentication to the admin account.
A cron job providing recurring execution of an external script.
A newly added SUID-root binary with potential privilege-escalation implications.

The combination of successful account access, persistence, and a potentially privileged executable warrants incident-response investigation.

What I Would Request Next

I would request:

File hash and timestamps for /opt/backup-tool/backup-agent.
Confirmation from the system/application owner that backup-agent is legitimate.
The full contents of x.sh and analysis of its behavior.
Authentication and command-execution logs for the admin account.
A check for other hosts communicating with 91.240.118.30.
Investigation for additional persistence mechanisms or suspicious files created after the successful login.
If compromise is confirmed, appropriate containment and credential-reset actions through the incident-response process.

Training scenario — simulated logs and evidence for practice, not a real incident
