import sqlite3
import pandas as pd

##################################  Open DB Connection ##################################
con = sqlite3.connect("detector.db")

##################################  Import Network ##################################
# load data
df = pd.read_csv('Network_Import.csv', skiprows=1)

# strip whitespace from headers
df.columns = df.columns.str.strip()

# drop data into database
df.to_sql("Network", con)

##################################  Import Network ##################################
# load data
df = pd.read_csv('Notification_Import.csv' , skiprows=1)

# strip whitespace from headers
df.columns = df.columns.str.strip()

# drop data into database
df.to_sql("Notification", con)

##################################  Import Email ##################################
# load data
df = pd.read_csv('Email_Import.csv', skiprows=1)

# strip whitespace from headers
df.columns = df.columns.str.strip()

# drop data into database
df.to_sql("Email", con)

##################################  Import Sensor ##################################
# load data
df = pd.read_csv('Sensor_Import.csv', skiprows=1)

# strip whitespace from headers
df.columns = df.columns.str.strip()

# drop data into database
df.to_sql("Sensor", con)

##################################  Import AnomalyProfiler ##################################
# load data
df = pd.read_csv('AnomalyProfiler_Import.csv', skiprows=1)

# strip whitespace from headers
df.columns = df.columns.str.strip()

# drop data into database
df.to_sql("AnomalyProfiler", con)


##################################  Close Connection ##################################
con.close()