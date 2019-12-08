
#!/bin/bash
echo "Starting db setup"
python /app/database.py

echo "Starting data import tool "
python /app/importer.py

echo "Starting monitoring script"
nohup bash /app/monitor.sh &


echo "Starting anomaly detector script"
nohup python /app/anomaly.py &


echo "Starting flask"
nohup python app.py &

echo "Container setup finished"
while true
do
echo ""
sleep 1000
done
