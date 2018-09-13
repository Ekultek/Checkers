# Checkers

Checkers is a tool that runs a series of commands on a system in order to determine everything about the system that could be needed to perform privilege escalation and or exploits.


```bash
usage: checkers.py [-h] [-a] [-o] [-s] [-n] [-u] [-f]

optional arguments:
  -h, --help            show this help message and exit
  -a, --all             check everything
  -o, --os              check the operating system
  -s, --apps-and-services
                        check the applications and services on the system
  -n, --networking      check the networking information of the system
  -u, --user-info       check for confidential user information on the system
  -f, --file-exposure   check the systems files (slow*)

```

# Installation
wget:
```
wget -O checkers.py https://git.io/fAiCs
```

cURL:
```
curl -o checkers.py https://git.io/fAiCs
```

Git:
```bash
git clone https://github.com/ekultek/checkers && cd checkers && python checkers.py
```
