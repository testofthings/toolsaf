FROM python:3.12-slim

WORKDIR /app

# Install Python dependencies
COPY requirements.txt /app
RUN pip install --no-cache-dir -r requirements.txt

# Install Graphviz
RUN apt update -y && apt install graphviz xdg-utils -y --no-install-recommends

# Install TDSAF
COPY tdsaf /app/tdsaf
COPY setup.py /app
RUN pip install --no-cache-dir -e .

# Copy Samples
#COPY /samples/basic-a app/samples

# Start TDSAF
ENTRYPOINT ["python", "statement.py"]
# Run container with:
# docker run -v ./<path-to-statement-dir>/statement.py:/app/statement.py -v <path-to-batch-dir>:/app/samples/ tdsaf -r /app/samples/
