![RootkitDetector Logo](https://mauricelambert.github.io/info/kernel/security/RootkitDetector_small.png "RootkitDetector logo")

# Rootkit Detector

## Description

This repository implements little programs to help SOC analysts to detect LKM rootkits on Linux.

### Hidden connections

Rootkits can hide network flux from `/proc/` and `recvmsg` kernel API.

#### How detection works

My little Go program compare the `/proc/net/` *file content* with sniffed packets from raw socket. When a sniffed packet is not visible in `/proc/net` *file content* this program print the IP and port for source and destination.

#### False positives

Some connections are closed by kernel before the program analysis (many udp connections and few tcp segment), you should identify the source and destination to identify legitimate packets.

#### Limits

 - Attackers should be active to detect it with this method.
 - I don't see any rootkit that hide connection from raw socket but it's possible, is not documented and probably not easy to implement.

### Hidden processes

Rootkits can hide processes by hiding the process directory in `/proc`.

#### How detection works

My little Go program try to access files content of all `/proc/<pid>` from PID 0 to the current process PID. When the script access a file and the PID directory is not present in the `/proc/` iteration, the program print the process executable and command line.

#### False positive

The linux operating system hide some process, you should identify executable and process to identify legitimate processes.

#### Limits

 - Attackers should be active to detect it with this method.
 - It's possible to hide and block all files in the hidden directory, there are maybe some impacts on process features but i didn't test yiet.
 - It's also possible to modify the PID on process creation, i don't see any implementation or documentation on internet.

### Kernel Hooking

To use rootkit features attackers should hooks syscalls and to hide connections attackers should hooks kernel functions.

#### How detection works

My script load a kernel module to print all syscalls addresses and few kernel functions addresses, parses the kernel logs file to get addresses and analyze addresses to found hooks.

#### False positive

I don't found any false positive in my tests but there are probably special cases.

#### Limits

 - Attackers can modify addresses before/after writing logs
 - Attackers can block kernel module load

#### Requirements

You should compile the kernel module for the target kernel version.

## Recommendations

**/!\ You should never use live investigation when offline investigations is possible !**

Risk: attackers will show your actions, alter results and performs irreversible malicious actions. Performing live investigations will remove attackers traces (like access files timestamps).

### Offline detections methods

 1. you should analyze a copy of raw hard disk to found the malicious kernel module, persistence files and malwares
 2. you should analyze the logs in the SIEM, with a good logging policy, you should have many traces of the first rootkit load, the exploit used to get remote code execution and the exploit used to elevate privileges. You should have networks traces in the SIEM to networks IOC and trust timestamps.
 3. you should analyze full memory dump to detect syscalls hooking and functions hooking
 4. reverse the rootkit (get it from disk analysis or memory analysis)

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
