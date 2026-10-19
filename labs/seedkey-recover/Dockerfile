FROM python:3.12-slim
WORKDIR /lab
COPY src/ /lab/src/
COPY labs/seedkey-recover/ /lab/
ENV PYTHONPATH=/lab/src
CMD ["python", "solve.py"]
