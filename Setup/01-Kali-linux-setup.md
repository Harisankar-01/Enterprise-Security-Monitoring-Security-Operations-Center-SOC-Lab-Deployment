## Installation
* Installed kali from <a href="https://www.kali.org/get-kali/#kali-platforms">Official Website</a>
  
##  Network Configuration
* Changed The Network setting of Kali to a isolated Nat Network named:SOC_LAB to isolate it from Host Machine
* Set a static ip configuration:
* 
```bash
nmcli con mod "Wired connection 1" ipv4.method manual \
  ipv4.addresses 192.168.1.5/24 \
  ipv4.gateway 192.168.1.1 \
  ipv4.dns 192.168.1.1
nmcli con up "Wired connection 1"
```

Verify:

```bash
ip a
ping -c 3 192.168.1.1
ping -c 3 192.168.1.9
```

## Update the System

```bash
sudo apt update && sudo apt full-upgrade -y
```
