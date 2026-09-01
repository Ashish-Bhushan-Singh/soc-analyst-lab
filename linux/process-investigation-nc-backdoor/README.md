Linux Process Investigation — Suspicious Listener Scenario

Training exercise — nc/4444 scenario is illustrative, not observed on a real compromised system.

Overview

This lab documents a Linux process and network investigation using common SOC analyst commands.

The exercise focused on:

Reviewing running processes with ps aux
Understanding parent-child process relationships
Reviewing listening network ports with ss -tulnp
Identifying suspicious process characteristics
Building a follow-up investigation plan
Scenario

The baseline Linux activity included expected processes and services such as init/systemd and sshd.

A constructed example of nc (netcat) listening on 0.0.0.0:4444 was used to practice identifying and investigating suspicious behavior.

Key Finding

The combination of:

nc acting as a listener
Port 4444
Binding to 0.0.0.0

is suspicious enough to investigate further.

The port number alone does not prove malicious activity. Netcat is a legitimate utility with legitimate uses, but it can also be abused for listeners, reverse shells, and other remote-access activity.

Investigation Methodology

The investigation approach was:

Identify the exact executable and command line using /proc/<PID>/exe and /proc/<PID>/cmdline.
Identify the parent process using pstree and process status information.
Confirm current network activity using ss.
Check for persistence through systemd, cron, shell startup files, and relevant logs.
Evidence

The complete investigation report, including the lab process and network output, is available in:

investigation.md

Training Notice

Training exercise — nc/4444 scenario is illustrative, not observed on a real compromised system.

This repository is for cybersecurity training and practice. It should not be interpreted as documentation of a real compromised system or real professional incident-response experience.
