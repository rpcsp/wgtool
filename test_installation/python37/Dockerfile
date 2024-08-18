FROM python:3.7-slim

WORKDIR /app

COPY wgtool wgtool
COPY requirements.txt requirements.txt
COPY src src

ENTRYPOINT [ "./wgtool" ]
