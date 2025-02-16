Syslog Daemon
```
cat /etc/rsyslog.d/50-default.con
#mail.info matches all messages produced by the kernel with severith of -ge 6/informational (0-6)
#mail.!info less than and not including 6/informational
```
Filtering syslog log files
```
cat /var/log/syslog | grep timesyncd
cat /var/log/syslog | grep -R "\w*.\w*.\w*"
```
log rotations
```
cat /etc/logrotate.conf
ls -l /var/log
```
Essential syslog types locations
  Authentication
  ```
last ./var/log/wtmp
last.*/var/log/wtmp #failed login attempts
```


Journald
```
#filtering logs by boot
jounalctl --list-boots
jounalctl -b b3076f6774b841e08c19236bf327f529

#filtering logs by a specific unit
journal -u ssh.service

#filtering logs since a specific time
journalctl -u ssh.service --since "2 days ago"
```
```
cat log.txt | grep "session opened" | wc -l
#searched in logged file
```

XML
```
xpath -q -e '//element/@attribute' file.xml
```

JSON
```
head <file> | jq .
jq '.' conn.log
jq '."id.orig_h"' conn.log | sort -u #get specific unique values
jq 'select(.resp_ip_bytes > 40) | .resp_ip_bytes' conn.log
#pull data from a group that is greater than 40
```
