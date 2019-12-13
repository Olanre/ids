import sqlite3
import pandas as pd

##################################  Open DB Connection ##################################
con = sqlite3.connect("detector.db")

##################################  Import Network ##################################
# load data
df = pd.read_csv('Network_Import.csv')

# strip whitespace from headers
df.columns = df.columns.str.strip()

# drop data into database
df.to_sql("network", con, if_exists='append', index=False)

##################################  Import Network ##################################
# load data
df = pd.read_csv('Notification_Import.csv')

# strip whitespace from headers
df.columns = df.columns.str.strip()

# drop data into database
df.to_sql("notification", con, if_exists='append', index=False)

##################################  Import Email ##################################
# load data
df = pd.read_csv('Email_Import.csv')

# strip whitespace from headers
df.columns = df.columns.str.strip()

# drop data into database
df.to_sql("email", con, if_exists='append', index=False)

##################################  Import Sensor ##################################
# load data
df = pd.read_csv('Sensor_Import.csv')

# strip whitespace from headers
df.columns = df.columns.str.strip()

# drop data into database
df.to_sql("sensor", con, if_exists='append', index=False)

##################################  Import AnomalyProfiler ##################################
# load data
df = pd.read_csv('AnomalyProfiler_Import.csv')

# strip whitespace from headers
df.columns = df.columns.str.strip()

# drop data into database
df.to_sql("anomalyProfiler", con, if_exists='append', index=False)


##################################  Close Connection ##################################
con.close()