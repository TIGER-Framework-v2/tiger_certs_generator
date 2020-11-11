FROM python:3.7-slim
WORKDIR /certs
COPY ./main.py /
RUN pip install --no-cache-dir pyopenssl
ENTRYPOINT ["python", "/main.py"]
