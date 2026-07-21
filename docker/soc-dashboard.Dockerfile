FROM python:3.11-slim
RUN pip install --no-cache-dir dash plotly pandas numpy
WORKDIR /app
COPY viz/dashboards/ ./viz/
EXPOSE 8050
CMD ["python", "viz/soc_realtime.py"]
