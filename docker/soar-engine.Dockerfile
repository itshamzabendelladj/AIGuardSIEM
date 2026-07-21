FROM python:3.11-slim
RUN pip install --no-cache-dir pyyaml kafka-python loguru
WORKDIR /app
COPY playbooks/ ./playbooks/
EXPOSE 9105
CMD ["python", "-m", "playbooks.engine"]
