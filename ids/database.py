
import sqlite3
from sqlite3 import Error


def create_connection(database):
    try:
        conn = sqlite3.connect(database, isolation_level=None, check_same_thread = False)
        conn.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
        return conn
    except Error as e:
        print(e)

def create_table(c,sql):
    log_query(sql)
    c.execute(sql)
    
def update_or_create_page(c,data):
    sql = "SELECT * FROM pages where name=? and session=?"
    c.execute(sql,data[:-1])
    result = c.fetchone()
    if result == None:
        create_pages(c,data)
    else:
        print(result)
        update_pages(c, result['id'])
 
def create_pages(c, data):
    print(data)
    sql = ''' INSERT INTO pages(name,session,first_visited)
              VALUES (?,?,?) '''
    c.execute(sql, data)
    
def update_pages(c, pageId):
    print(pageId)
    sql = ''' UPDATE pages
              SET visits = visits+1 
              WHERE id = ?'''
    c.execute(sql, [pageId])
    
def create_session(c, data):
    sql = ''' INSERT INTO sessions(ip, continent, country, city, os, browser, session, created_at)
              VALUES (?,?,?,?,?,?,?,?) '''
    c.execute(sql, data)
    
def select_all_sessions(c):
    sql = "SELECT * FROM sessions"
    c.execute(sql)
    rows = c.fetchall()
    return rows
    
def select_all_pages(c):
    sql = "SELECT * FROM pages"
    c.execute(sql)
    rows = c.fetchall()
    return rows
    
def select_all_user_visits(c, session_id):
    sql = "SELECT * FROM pages where session =?"
    c.execute(sql,[session_id])
    rows = c.fetchall()
    return rows

############################################################################################################################################
############################################  Creating and inserting into table ###########################################################
############################################################################################################################################
#    
#Make a new packet
def create_packet(c, data):
    sql = ''' INSERT INTO packets(TTL,DestinationAddr,Protocol,TotalLength,
            SourceAddr,EthernetProtocol,EthernetSrcAddr,EthernetDstAddr,FrameLength,
            FrameType,FrameNumber,ArrivalTime,InterfaceId,Length,DstPort,SrcPort, Flags, RawData)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) '''
  

#Add a new entry for the address entropy
def create_address_entropy(c, data):
    sql = ''' INSERT INTO addressEntropy(Sensor, Time, FirstPacket, LastPacket, SrcPacketScore, DstPacketScore, SrcByteScore, DstByteScore)
              VALUES (?,?,?,?,?,?,?,?) '''
    c.execute(sql, data)

#Add a new entry for the port entropy
def create_port_entropy(c, data):
    sql = ''' INSERT INTO portEntropy(Sensor, Time, FirstPacket, LastPacket, SrcPacketScore, DstPacketScore, SrcByteScore, DstByteScore)
              VALUES (?,?,?,?,?,?,?,?) '''
    c.execute(sql, data)        

#Add a new entry for the degree entropy
def create_degree_entropy(c, data):
    sql = ''' INSERT INTO portEntropy(Sensor, Time, FirstPacket, LastPacket, inDegreeScore, outDegreeScore)
              VALUES (?,?,?,?,?,?) '''
    c.execute(sql, data)

#Add a new sensor
def create_sensor(c, data):
    sql = ''' INSERT INTO Sensor(Name, Version)
              VALUES (?,?) '''
    c.execute(sql, data)

#Create a 1, 5 or 15 minute profiler
def create_profiler1minute(c, data):
    sql = ''' INSERT INTO Profiler1Minute(Sensor, EntropyThreshold)
              VALUES (?,?) '''
    c.execute(sql, data)

def create_profiler5minute(c, data):
    sql = ''' INSERT INTO Profiler5Minute(Sensor, EntropyThreshold)
              VALUES (?,?) '''
    c.execute(sql, data)

def create_profiler15minute(c, data):
    sql = ''' INSERT INTO Profiler15Minute(Sensor, EntropyThreshold)
              VALUES (?,?) '''
    c.execute(sql, data)

#get all the packets
def select_all_packets(c):
    sql = "SELECT * FROM packets"
    c.execute(sql)
    rows = c.fetchall()
    return rows

#get sensor responses
def select_sensor_responses(c, response_id):
    sql = "SELECT * FROM response where responsecode =?"
    c.execute(sql,[response_id])
    rows = c.fetchall()
    return rows

############################################################################################################################################
###################################  Getting Entropy By Source or Destination Address ######################################################
############################################################################################################################################
def select_source_address_bytes_in_time_range(c, starttime, endtime):
    sql = "SELECT SourceAddr, SUM(Length) as SumBytes from packets where ArrivalTime >= ? and ArrivalTime < ? Group By SourceAddr "
    c.execute(sql,[starttime, endtime])
    rows = c.fetchall()
    return rows

def select_destination_address_bytes_in_time_range(c, starttime, endtime):
    sql = "SELECT DestinationAddr, SUM(Length) as SumBytes from packets where ArrivalTime >= ? and ArrivalTime <= ? Group By DestinationAddr "
    c.execute(sql,[starttime, endtime])
    rows = c.fetchall()
    return rows

def select_source_address_bytes_in_id_range(c, startid, endid):
    sql = "SELECT SourceAddr, SUM(Length) as SumBytes from packets where PacketId >= ? and PacketId < ? Group By SourceAddr "
    c.execute(sql, [startid, endid])
    rows = c.fetchall()
    return rows

def select_destination_address_bytes_in_id_range(c, startid, endid):
    sql = "SELECT DestinationAddr, SUM(Length) as SumBytes from packets where PacketId >= ? and PacketId < ? Group By DestinationAddr "
    c.execute(sql, [startid, endid])
    rows = c.fetchall()
    return rows

def select_source_address_packets_in_time_range(c, starttime, endtime):
    sql = "SELECT SourceAddr, Count(SourceAddr) as Count from packets where ArrivalTime >= ? and ArrivalTime < ? Group By SourceAddr "
    c.execute(sql,[starttime, endtime])
    rows = c.fetchall()
    return rows

def select_destination_address_packets_in_time_range(c, starttime, endtime):
    sql = "SELECT DestinationAddr, Count(DestinationAddr) as Count from packets where ArrivalTime >= ? and ArrivalTime < ? Group By DestinationAddr "
    c.execute(sql,[starttime, endtime])
    rows = c.fetchall()
    return rows

def select_source_address_packets_in_id_range(c, startid, endid):
    sql = "SELECT SourceAddr, Count(SourceAddr) as Count from packets where PacketId >= ? and PacketId < ? Group By SourceAddr "
    c.execute(sql, [startid, endid])
    rows = c.fetchall()
    return rows

def select_destination_address_packets_in_id_range(c, startid, endid):
    sql = "SELECT DestinationAddr, Count(DestinationAddr) as Count from packets where PacketId >= ? and PacketId < ? Group By DestinationAddr "
    c.execute(sql, [startid, endid])
    rows = c.fetchall()
    return rows

############################################################################################################################################
#####################################  Getting Entropy By Source or Destination Port# ######################################################
############################################################################################################################################
def select_source_port_bytes_in_time_range(c, starttime, endtime):
    sql = "SELECT SrcPort, SUM(Length) as SumBytes from packets where ArrivalTime >= ? and ArrivalTime <= ? Group By SrcPort "
    c.execute(sql,[starttime, endtime])
    rows = c.fetchall()
    return rows

def select_destination_port_bytes_in_time_range(c, starttime, endtime):
    sql = "SELECT DstPort, SUM(Length) as SumBytes from packets where ArrivalTime >= ? and ArrivalTime <= ? Group By DstPort "
    c.execute(sql,[starttime, endtime])
    rows = c.fetchall()
    return rows

def select_source_port_bytes_in_id_range(c, startid, endid):
    sql = "SELECT SrcPort, SUM(Length) as SumBytes from packets where PacketId >= ? and PacketId < ? Group By SrcPort "
    c.execute(sql, [startid, endid])
    rows = c.fetchall()
    return rows

def select_destination_port_bytes_in_id_range(c, startid, endid):
    sql = "SELECT DstPort, SUM(Length) as SumBytes from packets where PacketId >= ? and PacketId < ? Group By DstPort "
    c.execute(sql, [startid, endid])
    rows = c.fetchall()
    return rows

def select_source_port_packets_in_time_range(c, starttime, endtime):
    sql = "SELECT SrcPort, Count(SrcPort) as Count from packets where ArrivalTime >= ? and ArrivalTime <= ? Group By SrcPort "
    c.execute(sql,[starttime, endtime])
    rows = c.fetchall()
    return rows

def select_destination_port_packets_in_time_range(c, starttime, endtime):
    sql = "SELECT DstPort, Count(DstPort) as Count from packets where ArrivalTime >= ? and ArrivalTime <= ? Group By DstPort "
    c.execute(sql,[starttime, endtime])
    rows = c.fetchall()
    return rows

def select_source_port_packets_in_id_range(c, startid, endid):
    sql = "SELECT SrcPort, Count(SrcPort) as Count from packets where PacketId >= ? and PacketId < ? Group By SrcPort "
    c.execute(sql, [startid, endid])
    rows = c.fetchall()
    return rows

def select_destination_port_packets_in_id_range(c, startid, endid):
    sql = "SELECT DstPort, Count(DstPort) as Count from packets where PacketId >= ? and PacketId < ? Group By DstPort "
    c.execute(sql, [startid, endid])
    rows = c.fetchall()
    return rows



############################################################################################################################################
#####################################  Getting Entropy By In and Out Degrees ######################################################
############################################################################################################################################
def select_out_degrees_in_time_range(c, starttime, endtime):
    sql = "SELECT SourceAddr, Count(Distinct DestinationAddr) as Count from packets where ArrivalTime >= ? and ArrivalTime <= ? Group By SourceAddr "
    c.execute(sql,[starttime, endtime])
    rows = c.fetchall()
    return rows

def select_in_degrees_in_time_range(c, starttime, endtime):
    sql = "SELECT DestinationAddr, Count(Distinct SourceAddr) as Count from packets where ArrivalTime >= ? and ArrivalTime <= ? Group By DestinationAddr "
    c.execute(sql,[starttime, endtime])
    rows = c.fetchall()
    return rows

def select_out_degrees_in_id_range(c, startid, endid):
    sql = "SELECT SourceAddr, Count(Distinct DestinationAddr) as Count from packets where  PacketId >= ? and PacketId < ? Group By SourceAddr "
    c.execute(sql, [startid, endid])
    rows = c.fetchall()
    return rows

def select_in_degrees_in_id_range(c, startid, endid):
    sql = "SELECT DestinationAddr, Count(Distinct SourceAddr) as Count from packets where PacketId >= ? and PacketId < ? Group By DestinationAddr "
    c.execute(sql, [startid, endid])
    rows = c.fetchall()
    return rows

############################################################################################################################################
###################################################  Getting Packets By Selector ###########################################################
############################################################################################################################################
def select_all_packets_in_time_range(c, starttime, endtime):
    sql = "SELECT * FROM packets where ArrivalTime >= ? and ArrivalTime <= ? "
    c.execute(sql, [starttime, endtime])
    rows = c.fetchall()
    return rows

def select_all_packets_in_id_range(c, startid, endid):
    sql = "SELECT * FROM packets where PacketId >= ? and PacketId < ? "
    c.execute(sql, [startid, endid])
    rows = c.fetchall()
    return rows

#Most Recent
def select_latest_packet(c):
    sql = "SELECT * FROM packets order By PacketId Desc limit 1 "
    c.execute(sql)
    rows = c.fetchone()[0]
    return rows

############################################################################################################################################
###################################################  Getting Entropies By Selector #########################################################
############################################################################################################################################
#By Sensor
def select_address_entropy_by_sensor(c, sensorId):
    sql = "SELECT * FROM addressEntropy where Sensor = ?  "
    c.execute(sql, [sensorId])
    rows = c.fetchall()
    return rows
    
def select_port_entropy_by_sensor(c, sensorId):
    sql = "SELECT * FROM portEntropy where Sensor = ?  "
    c.execute(sql, [sensorId])
    rows = c.fetchall()
    return rows

def select_degree_entropy_by_sensor(c, sensorId):
    sql = "SELECT * FROM degreeEntropy where Sensor = ?  "
    c.execute(sql, [sensorId])
    rows = c.fetchall()
    return rows

#By Id
def select_address_entropy_by_id(c, Id):
    sql = "SELECT * FROM addressEntropy where  Id = ?  "
    c.execute(sql, [Id])
    rows = c.fetchall()
    return rows

def select_port_entropy_by_id(c, Id):
    sql = "SELECT * FROM portEntropy where Id = ?  "
    c.execute(sql, [Id])
    rows = c.fetchall()
    return rows

def select_degree_entropy_by_id(c, Id):
    sql = "SELECT * FROM degreeEntropy where Id = ?  "
    c.execute(sql, [Id])
    rows = c.fetchall()
    return rows

#Most Recent
def select_latest_address_entropy(c):
    sql = "SELECT * FROM addressEntropy order By Id Desc limit 1 "
    c.execute(sql)
    rows = c.fetchone()[0]
    return rows

def select_latest_port_entropy(c):
    sql = "SELECT * FROM portEntropy order By Id Desc limit 1 "
    c.execute(sql)
    rows = c.fetchone()[0]
    return rows

def select_latest_degree_entropy(c):
    sql = "SELECT * FROM degreeEntropy order By Id Desc limit 1 "
    c.execute(sql)
    rows = c.fetchone()[0]
    return rows

############################################################################################################################################
###################################################       Getting Sensor Data      #########################################################
############################################################################################################################################
# Selection for 1 minute profiler
def select_minute1profiler(c):
    sql = """SELECT s.Name as SensorName, s.Version as Version, m.Sensor as Id, m.EntropyThreshold as Threshold from sensor s,  Profiler1Minute m where 
    s.SensorId = m.sensor  """
    c.execute(sql)
    rows = c.fetchall()
    return rows

def select_packets_by_minute1profiler_id(c, profile_id):
    sql = """SELECT * from packets where PacketId 
    in ( Select Packet from ReportsOn where Sensor in ( select Sensor from Profiler1Minute where Id = ?))"""
    c.execute(sql,[profile_id])
    rows = c.fetchall()
    return rows

def select_packets_by_minute1profiler_sensorid(c, sensor_id):
    sql = """SELECT * from packets where PacketId 
    in ( Select Packet from ReportsOn where Sensor in ( select Sensor from Profiler1Minute where Sensor = ?))"""
    c.execute(sql,[sensor_id])
    rows = c.fetchall()
    return rows

# Selection for 5 minute profiler
def select_minute5profiler(c):
    sql = """SELECT s.Name as SensorName, s.Version as Version, m.Sensor as Id, m.EntropyThreshold as Threshold from sensor s,  Profiler5Minute m where 
    s.SensorId = m.sensor  """
    c.execute(sql)
    rows = c.fetchall()
    return rows

def select_packets_by_minute5profiler_id(c, profile_id):
    sql = """SELECT * from packets where PacketId 
    in ( Select Packet from ReportsOn where Sensor in ( select Sensor from Profiler5Minute where Id = ?))"""
    c.execute(sql,[profile_id])
    rows = c.fetchall()
    return rows

def select_packets_by_minute5profiler_sensorid(c, sensor_id):
    sql = """SELECT * from packets where PacketId 
    in ( Select Packet from ReportsOn where Sensor in ( select Sensor from Profiler5Minute where Sensor = ?))"""
    c.execute(sql,[sensor_id])
    rows = c.fetchall()
    return rows


# Selection for 15 minute profiler
def select_minute15profiler(c):
    sql = """SELECT s.Name as SensorName, s.Version as Version, m.Sensor as Id, m.EntropyThreshold as Threshold from sensor s,  Profiler15Minute m where 
    s.SensorId = m.sensor  """
    c.execute(sql)
    rows = c.fetchall()
    return rows

def select_packets_by_minute15profiler_id(c, profile_id):
    sql = """SELECT * from packets where PacketId 
    in ( Select Packet from ReportsOn where Sensor in ( select Sensor from Profiler15Minute where Id = ?))"""
    c.execute(sql,[profile_id])
    rows = c.fetchall()
    return rows

def select_packets_by_minute1profiler_sensorid(c, sensor_id):
    sql = """SELECT * from packets where PacketId 
    in ( Select Packet from ReportsOn where Sensor in ( select Sensor from Profiler15Minute where Sensor = ?))"""
    c.execute(sql,[sensor_id])
    rows = c.fetchall()
    return rows

##################################  Getting Total Byes ##################################
def select_total_bytes_in_time_range(c, starttime, endtime):
    sql = "SELECT SUM(Length) as TotalBytes from packets where ArrivalTime >= ? and ArrivalTime <= ? "
    c.execute(sql,[starttime, endtime])
    rows = c.fetchall()
    return rows

def select_total_bytes_in_id_range(c, startid, endid):
    sql = "SELECT SUM(Length) as TotalBytes FROM packets where PacketId >= ? and PacketId < ? "
    c.execute(sql,[startid, endid])
    rows = c.fetchall()
    return rows

##################################  Getting Total Packets ##################################
def select_total_packets_in_time_range(c, starttime, endtime):
    sql = "SELECT Count(*) as TotalPackets from packets where ArrivalTime >= ? and ArrivalTime <= ? "
    c.execute(sql,[starttime, endtime])
    rows = c.fetchall()
    return rows

def select_total_packets_in_id_range(c, startid, endid):
    sql = "SELECT Count(*) as TotalPackets FROM packets where PacketId >= ? and PacketId < ? "
    c.execute(sql,[startid, endid])
    rows = c.fetchall()
    return rows

##################################  Getting Total Degrees ##################################
def select_total_distinct_source_hosts_in_time_range(c, starttime, endtime):
    sql = "SELECT Count(Distinct SourceAddr) as Count from packets where ArrivalTime >= ? and ArrivalTime <= ? "
    c.execute(sql,[starttime, endtime])
    rows = c.fetchall()
    return rows

def select_total_distinct_source_hosts_in_id_range(c, startid, endid):
    sql = "SELECT Count(Distinct SourceAddr) as Count from packets where PacketId >= ? and PacketId < ? "
    c.execute(sql,[startid, endid])
    rows = c.fetchall()
    return rows

def select_total_distinct_dest_hosts_in_time_range(c, starttime, endtime):
    sql = "SELECT Count(Distinct DestinationAddr) as Count from packets where ArrivalTime >= ? and ArrivalTime <= ? "
    c.execute(sql,[starttime, endtime])
    rows = c.fetchall()
    return rows

def select_total_distinct_dest_hosts_in_id_range(c, startid, endid):
    sql = "SELECT Count(Distinct DestinationAddr) as Count from packets where PacketId >= ? and PacketId < ? "
    c.execute(sql,[startid, endid])
    rows = c.fetchall()
    return rows

##################################  Utility queries ##################################
def log_query(sql):
    print"Executing the following sql query:\t" + sql + "\n\n")

 
def main():
    database = "./detector.db"
    sql_create_packets = """ 
        CREATE TABLE IF NOT EXISTS packets (
            PacketId INTEGER PRIMARY KEY AUTOINCREMENT,
            TTL INTEGER NOT NULL,
            DestinationAddr VARCHAR(20) NOT NULL,
            Protocol VARCHAR(30) NOT NULL,
            TotalLength INTEGER NOT NULL,
            SourceAddr VARCHAR(20) NOT NULL,
            EthernetProtocol VARCHAR(25) NOT NULL,
            EthernetSrcAddr VARHAR(20) NOT NULL,
            EthernetDstAddr VARCHAR(20) NOT NULL,
            FrameLength INTEGER NOT NULL,
            FrameType VARCHAR(14) NOT NULL,
            FrameNumber INTEGER NOT NULL,
            ArrivalTime TIMESTAMP NOT NULL,
            InterfaceId VARCHAR(30) NOT NULL,
            Length INTEGER NOT NULL,
            DstPort INTEGER NOT NULL,
            SrcPort INTEGER NOT NULL,
            Flags VARCHAR(20)  NOT NULL,
            RawData TEXT NOT NULL
        ); 
    """
    sql_create_network = """ 
        CREATE TABLE IF NOT EXISTS network (
            NetworkId INTEGER PRIMARY KEY AUTOINCREMENT,
            Name VARCHAR(50) NOT NULL ,
            CIDR VARCHAR(40) NOT NULL,
            Class VARCHAR(20)
        ); 
    """

    sql_create_sensor = """ 
        CREATE TABLE IF NOT EXISTS sensor (
            SensorId INTEGER PRIMARY KEY AUTOINCREMENT,
            Name VARCHAR(30) NOT NULL,
            Version VARCHAR (30)
        ); 
    """

    sql_create_Profiler1Minute = """ 
        CREATE TABLE IF NOT EXISTS Profiler1Minute (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Sensor INTEGER NOT NULL PRIMARY KEY,
            EntropyThreshold  REAL NOT NULL,
            FOREIGN KEY(Sensor) REFERENCES sensor(SensorId)
        ); 
    """

    sql_create_Profiler5Minute = """ 
        CREATE TABLE IF NOT EXISTS Profiler5Minute (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Sensor INTEGER NOT NULL PRIMARY KEY,
            EntropyThreshold REAL NOT NULL,
            FOREIGN KEY(Sensor) REFERENCES Sensor(SensorId)
        ); 
    """

    sql_create_Profiler15Minute = """ 
        CREATE TABLE IF NOT EXISTS Profiler15Minute (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Sensor INTEGER NOT NULL PRIMARY KEY ,
            EntropyThreshold REAL NOT NULL,
            FOREIGN KEY(Sensor) REFERENCES Sensor(SensorId)
        ); 
    """

    sql_create_residesin = """ 
        CREATE TABLE IF NOT EXISTS residesin (
            Packet  INTEGER NOT NULL,
            Network INTEGER NOT NULL,
            AssignmentDate TIMESTAMP NOT NULL,
            FOREIGN KEY(Packet) REFERENCES Packet(PacketId),
            FOREIGN KEY(Network) REFERENCES Network(NetworkId)
        ); 
    """

    sql_create_reportson = """ 
        CREATE TABLE IF NOT EXISTS reportson (
            Sensor  INTEGER NOT NULL,
            Packet  INTEGER NOT NULL,
            FOREIGN KEY(Packet) REFERENCES Packet(PacketId),
            FOREIGN KEY(Sensor) REFERENCES Sensor(SensorId)
        ); 
    """

    sql_create_addressEntropy = """ 
        CREATE TABLE IF NOT EXISTS addressEntropy (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Sensor  INTEGER NOT NULL,
            Time  TIMESTAMP NOT NULL,
            FirstPacket INTEGER NOT NULL,
            LastPacket INTEGER NOT NULL,
            SrcPacketScore  REAL NOT NULL,
            DstPacketScore REAL NOT NULL,
            SrcByteScore REAL NOT NULL,
            DstByteScore REAL NOT NULL,            
            FOREIGN KEY(FirstPacket) REFERENCES Packet(PacketId),
            FOREIGN KEY(LastPacket) REFERENCES Packet(PacketId),
            FOREIGN KEY(Sensor) REFERENCES Sensor(SensorId)
        ); 
    """

    sql_create_portEntropy = """ 
        CREATE TABLE IF NOT EXISTS portEntropy (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Sensor  INTEGER NOT NULL,
            Time  TIMESTAMP NOT NULL,
            FirstPacket INTEGER NOT NULL,
            LastPacket INTEGER NOT NULL,
            SrcPacketScore  REAL NOT NULL,
            DstPacketScore REAL NOT NULL,
            SrcByteScore REAL NOT NULL,
            DstByteScore REAL NOT NULL,
            FOREIGN KEY(FirstPacket) REFERENCES Packet(PacketId),
            FOREIGN KEY(LastPacket) REFERENCES Packet(PacketId),
            FOREIGN KEY(Sensor) REFERENCES Sensor(SensorId)
        ); 
    """

    sql_create_degreeEntropy = """ 
        CREATE TABLE IF NOT EXISTS degreeEntropy (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Sensor  INTEGER NOT NULL,
            Time  TIMESTAMP NOT NULL,
            FirstPacket INTEGER NOT NULL,
            LastPacket INTEGER NOT NULL,
            inDegreeScore  REAL NOT NULL,
            outDegreeScore REAL NOT NULL,           
            FOREIGN KEY(FirstPacket) REFERENCES Packet(PacketId),
            FOREIGN KEY(LastPacket) REFERENCES Packet(PacketId),
            FOREIGN KEY(Sensor) REFERENCES Sensor(SensorId)
        ); 
    """

    sql_create_response = """ 
        CREATE TABLE IF NOT EXISTS response (
            ResponseCode INTEGER PRIMARY KEY AUTOINCREMENT,
            Sensor  INTEGER NOT NULL,
            Threshold INTEGER NOT NULL,
            TimeSpan  INTEGER NOT NULL,
            TriggerDate TIMESTAMP NOT NULL,
            FOREIGN KEY(Sensor) REFERENCES Sensor(SensorId)
        ); 
    """

    sql_create_notification = """ 
        CREATE TABLE IF NOT EXISTS notification (
            Response INTEGER NOT NULL PRIMARY KEY,
            Name VARCHAR(50) NOT NULL,
            NotificationHubId INTEGER NOT NULL,
            FOREIGN KEY(Response) REFERENCES Response(ResponseCode)
        ); 
    """

    sql_create_email = """ 
        CREATE TABLE IF NOT EXISTS email (
            Response INTEGER NOT NULL PRIMARY KEY,
            RecipientAddress VARCHAR(50) NOT NULL,
            EmailMessage LONGTEXT NOT NULL,
            FOREIGN KEY(Response) REFERENCES Response(ResponseCode)
        ); 
    """
    
    # create a database connection
    conn = create_connection(database)
    if conn is not None:
        # create tables
        create_table(conn, sql_create_packets)
        create_table(conn, sql_create_network)
        create_table(conn, sql_create_Profiler1Minute)
        create_table(conn, sql_create_Profiler5Minute)
        create_table(conn, sql_create_Profiler15Minute)
        create_table(conn, sql_create_residesin)
        create_table(conn, sql_create_reportson)
        create_table(conn, sql_create_response)
        create_table(conn, sql_create_notification)
        create_table(conn, sql_create_email)
        create_table(conn, sql_create_addressEntropy)
        create_table(conn, sql_create_portEntropy)
        create_table(conn, sql_create_degreeEntropy)

        print("Connection established!")
    else:
        print("Could not establish connection")
        
if __name__ == '__main__':
    main()