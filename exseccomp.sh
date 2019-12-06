#! /bin/sh
cat /var/log/audit/audit.log | grep SECCOMP > auditlog.txt
/usr/bin/python3 ./translateseccomp3.py
