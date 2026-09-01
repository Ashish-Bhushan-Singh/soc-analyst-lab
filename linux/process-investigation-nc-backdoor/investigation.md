Linux Process Investigation — Suspicious Listener Scenario

Training exercise — nc/4444 scenario is illustrative, not observed on a real compromised system.

Scenario

Reviewed live process and port state on a Linux system using ps aux and ss -tulnp as part of SOC training.

The normal baseline included expected Linux processes and services such as init/systemd and sshd. A constructed suspicious example involving nc (netcat) listening on port 4444 was then analyzed to practice Linux process investigation methodology.

Evidence
1. Process Evidence — ps aux

The following section should contain the real output collected during the Linux lab.

Real lab output:
──(root㉿kali)-[/home]
└─# ps aux --sort=-%cpu | head -15   
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root       88164  100  0.0   9560  4516 pts/1    R+   09:00   0:00 ps aux --sort=-%cpu
root         786  1.3  3.5 509324 175628 tty7    Rsl+ 05:46   2:39 /usr/lib/xorg/Xorg :0 -seat seat0 -auth /var/run/lightdm/root/:0 -nolisten tcp vt7 -novtswitch
ashish      1352  0.6  0.0 215388  3276 ?        Sl   06:06   1:03 /usr/bin/VBoxClient --draganddrop
ashish      1430  0.4  2.8 1371708 140052 ?      Sl   06:06   0:49 xfwm4
ashish      1555  0.3  1.4 322804 73560 ?        Sl   06:06   0:35 /usr/lib/x86_64-linux-gnu/xfce4/panel/wrapper-2.0 /usr/lib/x86_64-linux-gnu/xfce4/panel/plugins/libcpugraph.so 13 25165836 cpugraph CPU Graph Graphical representation of the CPU load
ashish      1557  0.3  0.6 277084 30464 ?        Sl   06:06   0:32 /usr/lib/x86_64-linux-gnu/xfce4/panel/wrapper-2.0 /usr/lib/x86_64-linux-gnu/xfce4/panel/plugins/libgenmon.so 15 25165838 genmon Generic Monitor Show output of a command.
ashish     87733  0.3  0.1   8492  5460 pts/2    Ss+  08:59   0:00 -bash
root       80262  0.2  0.0      0     0 ?        I    08:44   0:02 [kworker/1:3-ata_sff]
root       87700  0.2  0.2  20060 13216 ?        Ss   08:59   0:00 sshd-session: ashish [priv]
ashish      2609  0.2  1.4 814644 73092 ?        Sl   06:06   0:22 /usr/bin/qterminal
root         722  0.1  0.0 352948  2860 ?        Sl   05:46   0:16 /usr/bin/VBoxDRMClient
root       86274  0.1  0.0      0     0 ?        I    08:56   0:00 [kworker/1:1-events_freezable_pwr_efficient]
root       75528  0.1  0.0      0     0 ?        I    08:34   0:01 [kworker/1:2-ata_sff]
ashish      1345  0.0  0.0 214872  3424 ?        Sl   06:06   0:10 /usr/bin/VBoxClient --seamless

The important fields for initial process review are the user, PID, CPU/memory usage, and especially the COMMAND column.

2. Network Evidence — ss -tulnp

The following section should contain the real listening-port output collected during the Linux lab.

Real lab output:

┌──(root㉿kali)-[/home]
└─# sudo ss -tulnp                                                                                            
Netid    State     Recv-Q    Send-Q       Local Address:Port         Peer Address:Port    Process                             
tcp      LISTEN    0         128                0.0.0.0:22                0.0.0.0:*        users:(("sshd",pid=87253,fd=6))    
tcp      LISTEN    0         128                   [::]:22                   [::]:*        users:(("sshd",pid=87253,fd=7))    


Normal services such as SSH should be evaluated according to the expected baseline for the system.

3. Constructed Suspicious Example

The following is an illustrative example used for training:

USER=root  COMMAND=/tmp/.hidden/x1


The suspicious listener scenario discussed during the exercise was:

nc listening on 0.0.0.0:4444


This example is not evidence of a real compromised system.

Analysis

The nc process is suspicious because netcat is a legitimate networking utility but can also be used to create simple listeners or support remote shells. A netcat listener should therefore be investigated when it appears unexpectedly.

Port 4444 is also notable because it is commonly seen in security labs and examples involving reverse shells and remote-control activity. The port number alone does not prove malicious activity, but it increases the reason to investigate when combined with an unexpected netcat listener.

The 0.0.0.0:4444 binding means the service is listening on all IPv4 interfaces. This can make the listener reachable from other systems on the network, depending on firewall and routing controls.

The combination of an unexpected nc listener, port 4444, and binding to all IPv4 interfaces is therefore suspicious and warrants further investigation.

Investigation Steps
1. Identify the exact process and executable

For the suspicious PID, first determine exactly what executable is running and what command was used:

ps -fp <PID>
sudo ls -l /proc/<PID>/exe
sudo cat /proc/<PID>/cmdline


This helps avoid relying only on the process name, which could potentially be misleading.

2. Identify the parent process

Determine which process started the suspicious process:

pstree -sp <PID>
sudo cat /proc/<PID>/status


The parent-child relationship can help establish how the process was launched.

3. Confirm network activity

Check whether the process currently has network connections:

sudo ss -tnp | grep ':4444'


This can help determine whether the listener has active connections.

4. Check for persistence

If the process remains suspicious, investigate whether it was configured to start again automatically.

Areas to review include:

systemd services
cron jobs
shell startup files
relevant authentication logs
other persistence mechanisms appropriate to the system
Disposition

The constructed nc listener on port 4444 should be treated as suspicious rather than immediately declared malicious.

The appropriate next step is to identify the executable, command line, parent process, network connections, and possible persistence mechanisms before determining the full impact.

This demonstrates the L1 investigation approach of validating the process and its behavior rather than making a conclusion based on a single indicator.

Training Notice

Training exercise — nc/4444 scenario is illustrative, not observed on a real compromised system.

The ps aux and ss -tulnp sections should contain only the user's own simulated/lab output. No real production IP addresses, usernames, hostnames, or company information should be committed to the repository.
