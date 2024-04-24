# API server

Framework can run API server, either for single security statement or it can load statements dynamically
by _launcher_.

The API is used by [tcsfw UI](https://github.com/ouspg/tcsfw-ui). The UI is simple Vue-project. The UI uses the API server as backend.
Note that using UI with the launcher requires _Nginx_ proxy setup, see UI documentation.

## One statement server

 The API for single security statemnt is activated by argument `--http-server`.  The following starts the server to port 81880 with access token `xxx`.

    $ TCSFW_SERVER_API_KEY=xxx python statement.py --http-server 8180

You can combine in `--read` and other command-line options to have content to serve.

## Server by launcher

The launcher is started in the following manner to default port 8180.

    $ python tcsfw/launcher.py

Launcher accepts incoming requests and starts security statement instances with local DB.
The request url must be `statement/` appended by the statement file path and name without `.py`.
Each new statement runs in separate process in different local API port from range 10000-19999.
For example, the following accesses the security statement from above example:
`http://localhost:8180/statements/statement`.

The UI cannot directly connect to the launcher, but requires a _Nginx_ 
proxy setup, see [UI](https://github.com/ouspg/tcsfw-ui) documentation.

## Docker container

A `Dockerfile` hosting one or more security statements should look something like this:
```Dockerfile
FROM python:3.11-slim

WORKDIR /app

# install dependencies without caching
COPY requirements.txt /app
RUN pip install --no-cache-dir -r requirements.txt

# install framework
COPY tcsfw /app/tcsfw
COPY setup.py /app
RUN pip install --no-cache-dir -e .

# copy security statements file(s)
COPY statement.py /app

# run the entry point
# ENV TCSFW_SERVER_API_KEY= # set in compose etc.
CMD ["python", "tcsfw/launcher.py", "--listen-port", "8180"]
```

This container is built and started as follows:

    $ docker build -t tcsfw/api-server .
    $ docker run -it -p 8180:8180 tcsfw/api-server

Instead of the security statement `.py` file, the entry point to the container is _launcher_ `tcsfw/launcher.py`.

See instructions in [tcsfw UI](https://github.com/ouspg/tcsfw-ui) documentation how to use the container with _Docker compose_.
