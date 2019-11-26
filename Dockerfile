FROM python:3.7-buster
# Create app directory
WORKDIR /app

#activate virtual environment
RUN python3 -m venv .venv

RUN apt-get update 
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install tshark
#RUN tshark-install.sh
RUN apt-get install -y screen tcpdump iputils-ping traceroute net-tools less screen
RUN apt-get install -y sqlite3 libsqlite3-dev 

# Install app dependencies
COPY requirements.txt ./

RUN pip install -r requirements.txt

RUN mkdir /app/pcap
COPY small.pcap /app/pcap

RUN apt-get install -y vim
#copy core script
COPY startup.sh ./

# Bundle app source
COPY ids /app
#RUN ["/bin/bash","/app/monitor.sh"]
#RUN ["python","/app/database.py"]


EXPOSE 5000
#ENTRYPOINT [ "python", "app.py" ]
ENTRYPOINT ["/bin/bash", "startup.sh"]