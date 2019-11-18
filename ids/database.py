
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
    
def create_packet(c, data):
    sql = ''' INSERT INTO packet(TTL,DestinationAddr,Protocol,TotalLength,
            SourceAddr,EthernetProtocol,EthernetSrcAddr,EthernetDstAddr,FrameLength,
            FrameType,FrameNumber,ArrivalTime,InterfaceId,Length,DstPort,SrcPort,
            Flags)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) '''
    c.execute(sql, data)
    
def select_all_packets(c):
    sql = "SELECT * FROM packets"
    c.execute(sql)
    rows = c.fetchall()
    return rows

def select_all_packets_in_range(c, arrivaltime):
    sql = "SELECT * FROM packets where ArrivalTime "
    c.execute(sql)
    rows = c.fetchall()
    return rows
    
def select_dos_packets_by_id(c, sensor_id):
    sql = """SELECT * from packet where PacketId 
    in ( Select Packet from ReportsOn where Sensor in ( select Sensor from dos where id = ?))"""
    c.execute(sql,[sensor_id])
    rows = c.fetchall()
    return rows

def select_dictionary_packets_by_id(c, sensor_id):
    sql = """SELECT * from packet where PacketId 
    in ( Select Packet from ReportsOn where Sensor in ( select Sensor from dictionaryattack where id = ?))"""
    c.execute(sql,[sensor_id])
    rows = c.fetchall()
    return rows

def select_botnet_packets_by_id(c, sensor_id):
    sql = """SELECT * from packet where PacketId 
    in ( Select Packet from ReportsOn where Sensor in ( select Sensor from botnet where id = ?))"""
    c.execute(sql,[sensor_id])
    rows = c.fetchall()
    return rows
    
def select_sensor_responses(c, response_id):
    sql = "SELECT * FROM response where responsecode =?"
    c.execute(sql,[response_id])
    rows = c.fetchall()
    return rows
 
def main():
    database = "./detector.db"
    sql_create_packets = """ 
        CREATE TABLE IF NOT EXISTS packets (
            PacketId AUTOINCREMENT NOT NULL PRIMARY KEY,
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
            Flags VARCHAR(20) NOT NULL 
        ); 
    """
    sql_create_network = """ 
        CREATE TABLE IF NOT EXISTS network (
            NetworkId  AUTOINCREMENT NOT NULL PRIMARY KEY,
            Name VARCHAR(50) NOT NULL ,
            CIDR VARCHAR(40) NOT NULL,
            Class VARCHAR(20)
        ); 
    """

    sql_create_sensor = """ 
        CREATE TABLE IF NOT EXISTS sensor (
            SensorId  AUTOINCREMENT NOT NULL PRIMARY KEY,
            Name VARCHAR(30) NOT NULL,
            Version VARCHAR (30)
        ); 
    """

    sql_create_dos = """ 
        CREATE TABLE IF NOT EXISTS dos (
            Sensor INTEGER NOT NULL PRIMARY KEY,
            PacketThreshold  INTEGER NOT NULL,
            TimeFrameThreshold INTEGER NOT NULL,
            FOREIGN KEY(Sensor) REFERENCES sensor(SensorId)
        ); 
    """

    sql_create_dictionaryattack = """ 
        CREATE TABLE IF NOT EXISTS dictionaryattack (
            Sensor INTEGER NOT NULL PRIMARY KEY,
            PasswordThreshold INTEGER NOT NULL,
            TimeFrameThreshold INTEGER NOT NULL,
            FOREIGN KEY(Sensor) REFERENCES Sensor(SensorId)
        ); 
    """

    sql_create_botnet = """ 
        CREATE TABLE IF NOT EXISTS botnet (
            Sensor INTEGER NOT NULL PRIMARY KEY ,
            GivenName VARCHAR(50) NOT NULL,
            IpBlackList LONGTEXT NOT NULL,
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

    sql_create_response = """ 
        CREATE TABLE IF NOT EXISTS response (
            ResponseCode  AUTOINCREMENT NOT NULL PRIMARY KEY,
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

    sql_create_report = """ 
        CREATE TABLE IF NOT EXISTS report (
            Response INTEGER NOT NULL PRIMARY KEY,
            Name   VARCHAR(50) NOT NULL,
            Format VARCHAR(50) NOT NULL,
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
        create_table(conn, sql_create_dos)
        create_table(conn, sql_create_dictionaryattack)
        create_table(conn, sql_create_botnet)
        create_table(conn, sql_create_residesin)
        create_table(conn, sql_create_reportson)
        create_table(conn, sql_create_response)
        create_table(conn, sql_create_notification)
        create_table(conn, sql_create_report)
        create_table(conn, sql_create_email)
        print("Connection established!")
    else:
        print("Could not establish connection")
        
if __name__ == '__main__':
    main()