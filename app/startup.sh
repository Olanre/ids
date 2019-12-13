
#!/bin/bash
#some setup
rm -rf log
mkdir -p log
rm -f detector.db
rm -f nohup.out

#pip install -r requirements.txt

#initialize the Database
echo "Starting db setup"
python3 database.py >> log/database_creation.log 2>&1 &

sleep 5

#import the dummy rows for applicable table.
echo "Starting data import tool "
python3 importer.py >> log/importer.log 2>&1 &

sleep 5

#Spinning up the network monitor script which uses Pyshark
echo "Starting monitoring script"
nohup python3 monitor.py >> log/monitor_loader.log 2>&1 &
echo "Started background monitoring process $!"

sleep 5

#Starting the anomaly detection engine script
echo "Starting anomaly detector script"
touch log/anomaly.log
nohup python3 anomaly.py & >> log/anomaly_loader.log 2>&1 &

#Set up the web server for interactive view, display is on localhost port 5000
#echo "Starting flask"
#nohup python app.py &

echo "IDS setup finished"
