FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY cesd_kpi_python.py index.html ./
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "cesd_kpi_python:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
