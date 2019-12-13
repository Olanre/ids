#!/bin/bash
PIDFILE=monitor.pid

function doPoll {
	echo "monitor.py was not running, restarting it..."
	#rm -f $PIDFILE
	mkdir -p log
	nohup python3 monitor.py >> log/monitor.log 2>&1
	echo $! > $PIDFILE
}

function pollLoop {
	while true; do
		THEPID=""
		if [ -f $PIDFILE ] ; then
			THEPID="`cat $PIDFILE`"
		fi

		if [ "$THEPID" = "" ] ; then
			doPoll
		fi
	
		sleep 10
	done
}

pollLoop &

echo "Started background monitoring process $!"
