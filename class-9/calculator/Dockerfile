FROM python:3.11-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY calculadora.py .
EXPOSE 8080
CMD ["python",` "calculadora.py"]
