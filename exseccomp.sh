#! /bin/sh
cat /var/log/audit/audit.log | grep SECCOMP > auditlog.txt
/usr/bin/python3 ./translateseccomp2.py
