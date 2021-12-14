#!/bin/bash

git clone https://github.com/mbechler/marshalsec.git
cd marshalsec && mvn clean package -DskipTests
