FROM python:3.11-slim
RUN pip install --no-cache-dir onnxruntime numpy kafka-python pyyaml loguru
WORKDIR /app
COPY ml/ ./ml/
COPY config/ml_models/ ./config/
EXPOSE 9104
CMD ["python", "-m", "ml.inference.onnx_inference"]
