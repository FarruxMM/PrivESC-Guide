PrivESC Guide

`hostname

/proc/version
uname -a  /etc/issue
ps axjf   /etc/passwd


<kbd>sudo -l    env</kbd>


netstat -ano  -tulp


        Find files:

#find . -name flag1.txt:   find the file named “flag1.txt” in the current directory
  find /home -name flag1.txt:  find the file names “flag1.txt” in the /home  directory
  find / -type d -name config:   find the directory named config under “/”
find / -type f -perm 0777:   find files with the 777 permissions (files readable, writable, and executable by all users)
find / -perm a=x:   find executable files
find /home -user frank:   find all files for user “frank” under “/home”
find / -mtime 10:   find files that were modified in the last 10 days
find / -atime 10:   find files that were accessed in the last 10 day
find / -cmin -60:   find files changed within the last hour (60 minutes)
find / -amin -60:  find files accesses within the last hour (60 minutes)
find / -size 50M:   find files with a 50 MB size


    Folders and files that can be written to or executed from:

find / -writable -type d 2>/dev/null :   Find world-writeable folders
find / -perm -222 -type d 2>/dev/null:  Find world-writeable folders
find / -perm -o w -type d 2>/dev/null:  Find world-writeable folders

    Find development tools and supported languages:

find / -name perl*
find / -name python*
find / -name gcc*

    SUID bit
find / -perm -u=s -type f 2>/dev/null


LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS 

LinEnum: https://github.com/rebootuser/LinEnum

LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester 

Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration

Linux Priv Checker: https://github.com/linted/linuxprivchecker
