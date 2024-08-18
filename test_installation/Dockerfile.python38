FROM python:3.8-slim

WORKDIR /app

COPY wgtool wgtool
COPY requirements.txt requirements.txt
COPY src src

ENTRYPOINT [ "./wgtool" ]
