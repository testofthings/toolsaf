# Uploading Data to the API
This document explains how to upload security statement data to our API.

## 🚧 Disclaimers 🚧
* This document is under construction.
* **Our upcoming cloud service is not ready; as such, these features cannot be used.**

## Command Line Options

### Getting an API Key
Uploading data requires having an API key. However, at this moment you **cannot** get one.

However, if you are a Test of Things insider, you can store your API key in the default directory `<your home directory>/.toolsaf/.api_key`. This can be done from the command line with:
```shell
echo "<api-key>" > ~/.toolsaf/.api_key
```
Alternatively, you can use a custom file path for the API key file. Refer to the [Custom API Key Path](#custom-api-key-path) section.

### Setting the API URL
**AT THIS TIME THERE IS NO URL FOR THE API**

Toolsaf looks for the API URL in `<your home directory>/.toolsaf/api_url`. You can store the API URL there with:
```shell
echo "https://<api-url>:<api-port>" > ~/.toolsaf/api_url
```
If the URL is not set, Toolsaf will ask you to provide it before you are able to upload data.
```
$ python product/statement.py -u -r ../sample-data
Could not read API URL, file $HOME/.toolsaf/api_url not found
Enter URL for the API: https://
```

### Uploading Data
Security statements and tool output can be uploaded to the API using the `-u` or `--upload` arguments:
```shell
python product/statement.py -u -r ../sample-data
```
Remember to replace `product` with the correct directory name and `../sample-data` with the correct location of the tool data.

### Custom API Key Path
To use a custom path for your API key, use the `--key-path` argument:
```shell
python product/statement.py -u --key-path ../my-api-key
```

### Allow Insecure Connections
For **debugging purposes**, you can allow insecure API connections using the `--insecure` flag.
```shell
python product/statement.py -u --insecure -r ../sample-data
```