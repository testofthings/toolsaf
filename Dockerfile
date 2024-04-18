FROM python:3.11-slim

WORKDIR /app

# install dependencies without caching
COPY requirements.txt /app
RUN pip install --no-cache-dir -r requirements.txt

# install framework
COPY tcsfw /app/tcsfw
COPY setup.py /app
RUN pip install --no-cache-dir -e .

# copy samples in
COPY samples /app/samples

# run the entry point
# ENV TCSFW_SERVER_API_KEY= # set in compose etc.
CMD ["python", "tcsfw/launcher.py", "--listen-port", "8180"]
