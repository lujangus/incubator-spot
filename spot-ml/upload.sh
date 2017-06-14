#!/usr/bin/env bash

USER=$1
CLUSTER=$2
DIRNAME=$3

# exclude the hidden files, target, lib, project, src... except the assembled jar
rsync -v -a --include='target' --include='target/scala-2.11' --include='target/scala-2.11/spot-ml-assembly-1.1.jar' \
    --include='*.sh' --exclude='*' .  $USER@$CLUSTER:~/$DIRNAME