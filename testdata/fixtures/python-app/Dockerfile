FROM python:3.12-slim
ENV DB_PASSWORD=Sup3rS3cretPassw0rd
COPY . /app
RUN pip install -r /app/requirements.txt
USER root
CMD ["python", "/app/app.py"]
