#!/bin/bash

# wait-for-it.sh

TIMEOUT=10  # 최대 대기 시간 (초)
QUIET=0

echoerr() { if [[ "$QUIET" -ne 1 ]]; then echo "$@" 1>&2; fi }

usage() { echoerr "Usage: $0 host:port [-s] [-t timeout] [-- command args]"; exit 1; }

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -q|--quiet)
    QUIET=1
    shift
    ;;
    -s|--strict)
    STRICT=1
    shift
    ;;
    -t|--timeout)
    TIMEOUT="$2"
    shift 2
    ;;
    --)
    shift
    break
    ;;
    *)
    usage
    ;;
esac
done

hostport=$1
shift
command=$@

IFS=':' read -ra hostportarr <<< "$hostport"
host=${hostportarr[0]}
port=${hostportarr[1]}

timeleft=$(( TIMEOUT ))

while [[ $timeleft -gt 0 ]]
do
    echoerr "Trying to connect to $hostport..."
    nc -z "$host" "$port" > /dev/null 2>&1

    result=$?
    if [[ $result -eq 0 ]]; then
        if [[ "$STRICT" -eq 1 ]]; then
            echoerr "$hostport is up."
        fi
        break
    fi
    echoerr "$hostport is not yet up, waiting..."
    sleep 1
    timeleft=$(( timeleft-1 ))
done

if [[ $result -ne 0 ]]; then
    echoerr "Timed out waiting for $hostport"
    exit 1
fi

if [[ -n "$command" ]]; then
    exec $command
fi