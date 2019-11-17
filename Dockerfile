FROM python:3.7-slim-buster

MAINTANER Olanre "ookunlol@unb.com"

# Create app directory
WORKDIR /app

#activate virtual environment
RUN python3 -m venv .venv

# Install app dependencies
COPY simple-ids/requirements.txt ./
RUN pip install -r requirements.txt

# Bundle app source
COPY simple-ids /app

EXPOSE 8080
ENTRYPOINT [ "python", "app.py" ]