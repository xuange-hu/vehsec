FROM python:3.12-slim
WORKDIR /lab
COPY solve.py .
RUN pip install --no-cache-dir ecdsa
CMD ["python", "solve.py", "--gen", "20", "--reuse"]
