FROM python:3.10-slim

WORKDIR /app

# Copy API and updater requirements
COPY ./api/requirements.txt /app/api-requirements.txt
COPY ./updater/requirements.txt /app/updater-requirements.txt

# Install requirements
RUN pip install --no-cache-dir -r /app/api-requirements.txt
RUN pip install --no-cache-dir -r /app/updater-requirements.txt

# Copy API and updater code
COPY ./api/main.py /app/api_main.py
COPY ./updater/main.py /app/updater_main.py
COPY ./templates /app/templates
COPY utils.py /app/utils.py

# Expose port for FastAPI
EXPOSE 8000