# Uploading Data to the API
This document explains how to upload security statement data to our API.

## 🚧 Disclaimers 🚧
* This document is under construction.
* **Our upcoming cloud service is not ready, as such these features can not be used.**

## Command Line Options

### Getting an API Key
To upload data, you need an API key. You can register using either Google or GitHub OAuth with the following commands:
```shell
python product/statement.py --register-google
# OR
python product/statement.py --register-github
```
After completing the OAuth process, Toolsaf will prompt you for your API key and save it to `<your home directory>/.toolsaf/.api_key`. To use a custom file path, refer to the [Custom API Key Path](#custom-api-key-path) section.

### Uploading Data
Once you have a valid API key, you can upload statements and tool outputs to the API using `-u` or `--upload`.
```shell
python product/statement.py -u -r ../sample-data
```
By default, the API key is expected to be located in `<your home directory>/.toolsaf/.api_key`. To specify a custom file path, see the [Custom API Key Path](#custom-api-key-path) section.

### Custom API Key Path
To use a custom path for your API key, use the `--key-path` option:
```shell
python product/statement.py --register-github --key-path ../api_key

python product/statement.py --upload --key-path /home/my_stuff/api_key.txt
```

### Allow Insecure Connections
For debugging purposes, you can allow insecure API connections using the `--insecure` flag.
```shell
python product/statement.py -u ../api_key.txt --insecure -r ../sample-data
```

## Setting the API URL
**At this time there is no URL for our API.**

To upload data, the URL for our API must be set. When first using `-u`, `--register-google` or `--register-github` Toolsaf prompts you to enter the URL through the CLI. Alternatively you can add the URL into the file `$HOME/.toolsaf/api_url`.

Here is what Toolsaf will show / ask:
```
Could not read API URL, file /home/<user>/.toolsaf/api_url not found
Enter URL for the API: https://
```
Toolsaf will then write the URL to the displayed file