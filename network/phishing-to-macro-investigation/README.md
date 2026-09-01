Phishing-to-Macro Investigation

Training scenario — simulated logs for practice, not a real incident.

Overview

This Phase 2 capstone is a simulated SOC investigation that combines multiple network and endpoint evidence sources.

The investigation follows a suspected phishing-to-malicious-document execution chain involving:

Suspicious lookalike domains
DNS activity
Proxy traffic
Microsoft Word execution
PowerShell launched by Word
An encoded PowerShell command
Objective

The objective is to correlate DNS, proxy, and endpoint process evidence and determine whether the activity should be escalated for further investigation.

Investigation Report

Read the complete investigation here:

investigation.md

Evidence

The simulated evidence is stored in the evidence/ directory:

dns-log.txt — DNS queries from the workstation
proxy-log.txt — proxy activity and classification
endpoint-log.txt — endpoint process execution
Key Finding

The evidence is consistent with a possible phishing-to-malicious-document execution chain.

The suspicious domains were accessed from the Finance workstation, and shortly afterward Microsoft Word launched PowerShell with an encoded command. Because the available evidence does not establish the complete scope or impact, the appropriate disposition is escalation to L2.

Next Investigation Requests

The investigation recommends requesting:

The full encoded PowerShell command for decoding and analysis.
The original Word document and related phishing email.
Additional EDR/endpoint telemetry after the PowerShell execution.
A search for the same indicators on other Finance computers.
Training Notice

This repository contains simulated logs and analysis for cybersecurity training and practice.

Training scenario — simulated logs for practice, not a real incident.

The evidence and investigation should not be interpreted as documentation of a real security incident or real professional incident-response experience.
