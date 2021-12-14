#!/bin/bash

cd vuln
javac -cp apache-log4j-2.14.1-bin/log4j-core-2.14.1.jar:apache-log4j-2.14.1-bin/log4j-api-2.14.1.jar log4jhttp.java
java -cp apache-log4j-2.14.1-bin/log4j-core-2.14.1.jar:apache-log4j-2.14.1-bin/log4j-api-2.14.1.jar:. log4jhttp
