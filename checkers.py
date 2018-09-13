import os
import time
import shlex
import argparse
import subprocess


class Parser(argparse.ArgumentParser):

    def __int__(self):
        super(Parser, self).__init__()

    @staticmethod
    def optparse():
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-a", "--all", action="store_true", dest="checkAll", default=False, help="check everything"
        )
        parser.add_argument(
            "-o", "--os", action="store_true", dest="checkOS", default=False, help="check the operating system"
        )
        parser.add_argument(
            "-s", "--apps-and-services", action="store_true", dest="checkApps", default=False,
            help="check the applications and services on the system"
        )
        parser.add_argument(
            "-n", "--networking", action="store_true", dest="checkNetworking", default=False,
            help="check the networking information of the system"
        )
        parser.add_argument(
            "-u", "--user-info", action="store_true", dest="checkUserInfo", default=False,
            help="check for confidential user information on the system"
        )
        parser.add_argument(
            "-f", "--file-exposure", action="store_true", dest="checkFileSystem", default=False,
            help="check the systems files (slow*)"
        )
        return parser.parse_args()


OPERATING_SYSTEM_INFORMATION_COMMANDS = {
    "distribution information": [
        "cat /etc/issue", "cat /etc/*-release", "cat /etc/lsb-release", "cat /etc/redhat-release"
    ],
    "kernel information": [
        "cat /proc/version", "uname -a", "uname -mrs", "rpm -q kernel", "dmesg | grep Linux", "ls /boot | grep vmlinuz-"
    ],
    "environment variables": [
        "cat /etc/profile", "cat /etc/bashrc",
        "cat ~/.bash_profile", "cat ~/.bashrc",
        "cat ~/.bash_logout", "env", "set"
    ],
    "printer information": ["lpstat -a"]
}
APPLICATIONS_AND_SERVICES_COMMANDS = {
    "currently running processes": [
        "ps aux", "ps -ef", "cat /etc/services"
    ],
    "processes being run by root": [
        "ps aux | grep root", "ps -ef | grep root"
    ],
    "installed applications": [
        "ls -alh /usr/bin/", "ls -alh /sbin/", "dpkg -l", "rpm -qa",
        "ls -alh /var/cache/apt/archivesO", "ls -alh /var/cache/yum/"
    ],
    "application and service configurations": [
        "cat /etc/syslog.conf", "cat /etc/chttp.conf", "cat /etc/lighttpd.conf",
        "cat /etc/cups/cupsd.conf", "cat /etc/inetd.conf", "cat /etc/apache2/apache2.conf",
        "cat /etc/my.conf", "cat /etc/httpd/conf/httpd.conf", "cat /opt/lampp/etc/httpd.conf",
        'ls -aRl /etc/ | awk \'$1 ~ /^.*r.*/\''
    ],
    "scheduled jobs": [
        "crontab -l", "ls -alh /var/spool/cron", "ls -al /etc/ | grep cron",
        "ls -al /etc/cron*", "cat /etc/cron*", "cat /etc/at.allow", "cat /etc/at.deny",
        "cat /etc/cron.allow", "cat /etc/cron.deny", "cat /etc/crontab",
        "cat /etc/anacrontab", "cat /var/spool/cron/crontabs/root"
    ]
}
NETWORKING_COMMUNICATION_COMMANDS = {
    "NIC information": ["/sbin/ifconfig -a", "cat /etc/network/interfaces", "cat /etc/sysconfig/network"],
    "networking configurations": [
        "cat /etc/resolv.conf", "cat /etc/sysconfig/network",
        "cat /etc/networks", "iptables -S", "ufw status numbered", "hostname", "dnsdomainname",
    ],
    "other communications with the server": [
        "netstat -antup", "netstat -antpx", "netstat -tulpn"
    ],
    "cached networking information": ["arp -e", "route", "/sbin/route -nee"],

}
CONFIDENTIAL_USER_INFORMATION_DISCLOSURE_COMMANDS = {
    "who can do what": [
        "id", "who", "w", "last", "cat /etc/passwd | cut -d: -f1",
        "grep -v -E \"^#\" /etc/passwd | awk -F: '$3 == 0 { print $1}'",
        "awk -F: '($3 == \"0\") {print}' /etc/passwd", "cat /etc/sudoers"
    ],
    "plaintext usernames and passwords": [
        "grep -i user /*", "grep -i pass /*", "grep -C 5 \"password\" /*",
        "find . -name \"*.php\" -print0 | xargs -0 grep -i -n \"var $password\""
    ],
    "sensitive file disclosure": [
        "cat /etc/passwd", "cat /etc/group", "cat /etc/shadow", "ls -alh /var/mail/"
    ],
    "home directory files": ["ls -ahlR /root/", "ls -ahlR /home/"],
    "default password locations": [
        "cat /var/apache2/config.inc", "cat /var/lib/mysql/mysql/user.MYD", "cat /root/anaconda-ks.cfg"
    ],
    "current user history information": [
        "cat ~/.bash_history", "cat ~/.nano_history",
        "cat ~/.atftp_history", "cat ~/.mysql_history","cat ~/.php_history"
    ],
    "private keys": [
        "cat ~/.ssh/authorized_keys", "cat ~/.ssh/identity.pub",
        "cat ~/.ssh/identity", "cat ~/.ssh/id_rsa.pub", "cat ~/.ssh/id_rsa",
        "cat ~/.ssh/id_dsa.pub", "cat ~/.ssh/id_dsa", "cat /etc/ssh/ssh_config",
        "cat /etc/ssh/sshd_config", "cat /etc/ssh/ssh_host_dsa_key.pub",
        "cat /etc/ssh/ssh_host_dsa_key", "cat /etc/ssh/ssh_host_rsa_key.pub",
        "cat /etc/ssh/ssh_host_rsa_key", "cat /etc/ssh/ssh_host_key.pub", "cat /etc/ssh/ssh_host_key"
    ]
}
FILE_SYSTEM_EXPOSURE_COMMANDS = {
    "configuration files that can be written": [
        "ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null",
        "ls -aRl /etc/ | awk '$1 ~ /^..w/' 2>/dev/null",
        "ls -aRl /etc/ | awk '$1 ~ /^.....w/' 2>/dev/null",
        "ls -aRl /etc/ | awk '$1 ~ /w.$/' 2>/dev/null",
        "find /etc/ -readable -type f 2>/dev/null",
        "find /etc/ -readable -type f -maxdepth 1 2>/dev/null"
    ],
    "files in var": [
        "ls -alh /var/log", "ls -alh /var/mail",
        "ls -alh /var/spool", "ls -alh /var/spool/lpd",
        "ls -alh /var/lib/pgsql", "ls -alh /var/lib/mysql",
        "cat /var/lib/dhcp3/dhclient.leases"
    ],
    "hidden settings files": [
        "ls -alhR /var/www/", "ls -alhR /srv/www/htdocs/",
        "ls -alhR /usr/local/www/apache22/data/", "ls -alhR /opt/lampp/htdocs/",
        "ls -alhR /var/www/html/"
    ],
    "log files": [
        "cat /etc/httpd/logs/access_log", "cat /etc/httpd/logs/error_log",
        "cat /var/log/apache2/access_log", "cat /var/log/apache2/error_log",
        "cat /var/log/apache/access_log", "cat /var/log/auth.log",
        "cat /var/log/chttp.log", "cat /var/log/cups/error_log",
        "cat /var/log/dpkg.log", "cat /var/log/faillog", "cat /var/log/httpd/access_log",
        "cat /var/log/httpd/access.log", "cat /var/log/httpd/error_log",
        "cat /var/log/httpd/error.log", "cat /var/log/lastlog",
        "cat /var/log/lighttpd/access.log", "cat /var/log/lighttpd/error.log",
        "cat /var/log/lighttpd/lighttpd.access.log",
        "cat /var/log/lighttpd/lighttpd.error.log", "cat /var/log/messages",
        "cat /var/log/secure", "cat /var/log/syslog",
        "cat /var/log/wtmp", "cat /var/log/xferlog", "cat /var/log/yum.log",
        "cat /var/run/utmp", "cat /var/webmin/miniserv.log",
        "cat /var/www/logs/access_log", "cat /var/www/logs/access.log",
        "ls -alh /var/lib/dhcp3/", "ls -alh /var/log/postgresql/",
        "ls -alh /var/log/proftpd/", "ls -alh /var/log/samba/"
    ],
    "unmounted filesystems": [
        "cat /etc/fstab"
    ],
    "advanced file permissions": [
        "find / -perm -1000 -type d 2>/dev/null", "find / -perm -g=s -type f 2>/dev/null",
        "find / -perm -u=s -type f 2>/dev/null",
        "find / -perm -g=s -o -perm -u=s -type f 2>/dev/null",
        "for i in `locate -r \"bin$\"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done",
        "find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null"
    ],
    "common execution spots": [
        "find / -writable -type d 2>/dev/null", "find / -perm -222 -type d 2>/dev/null",
        "find / -perm -o w -type d 2>/dev/null", "find / -perm -o x -type d 2>/dev/null",
        "find / \( -perm -o w -perm -o x \) -type d 2>/dev/null"
    ],
    "problem files": [
        "find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print",
        "find /dir -xdev \( -nouser -o -nogroup \) -print"
    ],
    "development tools and languages": [
        "find / -name perl*", "find / -name python*", "find / -name gcc*", "find / -name cc"
    ],
    "how can files be uploaded": [
        "find / -name wget", "find / -name nc*", "find / -name netcat*", "find / -name tftp*", "find / -name ftp"
    ]
}


def run_command(command):
    command = shlex.split(command)
    try:
        proc = subprocess.check_output(command)
        if not proc:
            return None
        return proc
    except subprocess.CalledProcessError:
        return None
    except OSError:
        return None
    except AttributeError:
        try:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE)
            res = proc.communicate()[0]
            if res:
                return res
        except:
            return None


def main():
    opt = Parser().optparse()
    folder_path = "{root}/post_check_results_{current}".format(root=os.getcwd(), current=time.strftime("%H%M%S"))
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    to_check = []
    done = []
    if opt.checkAll:
        to_check.append(OPERATING_SYSTEM_INFORMATION_COMMANDS)
        to_check.append(APPLICATIONS_AND_SERVICES_COMMANDS)
        to_check.append(NETWORKING_COMMUNICATION_COMMANDS)
        to_check.append(CONFIDENTIAL_USER_INFORMATION_DISCLOSURE_COMMANDS)
        to_check.append(FILE_SYSTEM_EXPOSURE_COMMANDS)
    if opt.checkOS:
        to_check.append(OPERATING_SYSTEM_INFORMATION_COMMANDS)
    if opt.checkApps:
        to_check.append(APPLICATIONS_AND_SERVICES_COMMANDS)
    if opt.checkNetworking:
        to_check.append(NETWORKING_COMMUNICATION_COMMANDS)
    if opt.checkUserInfo:
        to_check.append(CONFIDENTIAL_USER_INFORMATION_DISCLOSURE_COMMANDS)
    if opt.checkFileSystem:
        to_check.append(FILE_SYSTEM_EXPOSURE_COMMANDS)

    if len(to_check) != 0:
        for constant in to_check:
            for k in constant.keys():
                if k not in done:
                    file_path = "{path}/{filename}.txt".format(
                        path=folder_path, filename=str(k).replace(" ", "_")
                    )
                    with open(file_path, "a+") as results:
                        print("\n\n[*] checking {key}\n\n".format(key=k))
                        print("-" * 30)
                        for command in constant[k]:
                            res = run_command(command)
                            if res is not None:
                                results.write(
                                    "RESULTS FROM COMMAND: {com}\n{sep}\n{results}\n{sep}\n\n".format(
                                       com=command, sep="-" * 30, results=res
                                    )
                                )
                        print("-" * 30)
                        done.append(k)
                else:
                    print("[~] already done that")
    else:
        print("[!] must specify something to search")
        os.remove(folder_path)
    print("[!] done, remember to use `kill -9 $$` to prevent bash history!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[!] i guess you found what you wanted, remember to use `kill -9 $$` to prevent bash history!")
