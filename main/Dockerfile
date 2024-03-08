FROM python:3.12.1-alpine3.19
WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY ../.. .

ENV SERVER_PORT=8080

CMD ["sh", "-c", "exec python3 -m flask run --host=0.0.0.0 --port=$SERVER_PORT"] 
