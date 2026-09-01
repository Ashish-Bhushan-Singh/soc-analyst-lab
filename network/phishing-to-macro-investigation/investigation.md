Phishing-to-Macro Investigation

Training scenario — simulated logs for practice, not a real incident.

Scenario / Objective

This investigation examines simulated evidence from one Finance workstation, finance-pc03, associated with user mrodriguez.

The objective is to correlate DNS, proxy, and endpoint process activity to determine whether the workstation may have been affected by a phishing attack involving a malicious Word document and PowerShell execution.

Evidence
Evidence 1 — DNS Logs

The workstation queried two suspicious domains:

11:00:00  finance-pc03  DNS A   paypal-secure-verify.com
11:00:05  finance-pc03  DNS A   billing-update-portal.net
11:00:05  finance-pc03  DNS A   billing-update-portal.net
11:00:06  finance-pc03  DNS A   billing-update-portal.net


The domains appear to use brand or billing-related names intended to make them look legitimate.

Evidence 2 — Proxy Logs

The proxy recorded allowed connections to the same domains:

11:00:01  PROXY  user=mrodriguez  src=10.20.3.15  dst=paypal-secure-verify.com  action=ALLOWED  category=uncategorized
11:00:06  PROXY  user=mrodriguez  src=10.20.3.15  dst=billing-update-portal.net  action=ALLOWED  category=uncategorized


Both domains were marked uncategorized and the traffic was allowed.

Evidence 3 — Endpoint Process Log

A few minutes later, the endpoint recorded Word launching PowerShell:

11:03:12  finance-pc03  process=powershell.exe  parent=winword.exe  user=mrodriguez  cmdline="powershell.exe -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA..."


The -enc parameter indicates that the PowerShell command was encoded.

Analysis

The DNS and proxy evidence shows that finance-pc03 accessed domains that appear to impersonate PayPal or a billing service. This is consistent with phishing using deceptive or lookalike domains to trick a user into visiting a malicious site.

The proxy allowed the traffic because the domains were classified as uncategorized. This means the proxy did not have a known malicious classification for them at the time. ALLOWED therefore does not mean the domains were verified as safe; it means the proxy had no rule or reputation verdict that caused the traffic to be blocked.

The endpoint evidence is more suspicious. Microsoft Word (winword.exe) launching PowerShell is unusual because a normal Word document does not normally need to start PowerShell. This parent-child relationship is consistent with a potentially malicious Word document using a macro or embedded content to execute PowerShell.

Taken together, the evidence forms a connected timeline: the user or workstation interacted with phishing-related domains, the proxy allowed the traffic because the domains were not classified as malicious, and shortly afterward Word launched PowerShell with an encoded command. This combination is consistent with a possible phishing-to-malicious-document execution chain.

Disposition + Escalation Reasoning

Disposition: Escalate to L2.

The incident should be escalated because multiple independent evidence sources support the same suspicious activity:

Suspicious brand-impersonation domains were queried.
The workstation connected to those domains through the proxy.
The proxy classified the domains as uncategorized and allowed the traffic.
Word launched PowerShell shortly afterward.
PowerShell used an encoded command.

The evidence is strong enough to indicate a possible compromise, but the available logs do not yet show exactly what the PowerShell command did or how far the activity progressed. L2 should continue the investigation rather than closing the alert or simply monitoring it.

What I'd Request Next

Decode the full PowerShell command.
The -enc parameter indicates an encoded command. Decoding the complete command would help determine whether it downloaded malware, contacted command-and-control infrastructure, performed reconnaissance, or carried out another action.

Obtain the original Word document and related email.
The investigation should identify whether the Word document arrived as an email attachment or through another delivery method. The sender, subject, attachment, and other recipients should be reviewed.

Request additional EDR/endpoint telemetry after 11:03.
This should include subsequent child processes, file creation, network connections, registry activity, and other endpoint behavior to determine whether execution continued.

Check other Finance computers for the same activity.
Search for the same domains, email indicators, Word-to-PowerShell execution, and related activity on other systems to determine whether this was an isolated event or part of a wider phishing campaign.

Conclusion

The simulated evidence supports escalation of a suspected phishing-to-malicious-document execution chain. The available evidence does not by itself establish the full scope or impact of the compromise, so additional endpoint, email, and PowerShell evidence should be collected by L2.

Training scenario — simulated logs for practice, not a real incident.
