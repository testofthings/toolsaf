# API client tool

The `tcsfw` command invokes the API client tool.

    $ tcsfw

As default, a short help is printed out.
The tool main file is `tcsfw/client_tool.py`, which can be called instead.

## Get API keys

The following prompts for password of user `user1` and then fetches new API key for the ruuvi sample statement.

    $ tcsfw get-key --user user1 \
       --url http://192.168.1.1/login/samples/ruuvi/ruuvi

The API key is printed out, but with argument `--save` it is saved into known file `.tcsfw_api_key` which is read by other client subcommands.
From now on, the API key assumed to be saved in this file.
Alternatively, it can be given with `--api-key` command-line argument.

## Upload tool output

Supported tool output files can be uploaded with subcommand `upload`.

    $ tcsfw upload --read <path-to-results> \
       --url http://192.168.1.1/samples/ruuvi/ruuvi


The uploaded directories and files must stick with the [supported formats](Tools.md).

## Reload

Security statement can be reloaded, and stored data reapplied with reload subcommand.
JSON parameter can be provided to clear thre DB to avoid reapplying data, e.g.:

    $ tcsfw reset --param '{"clear_db": true}'
        --url http://192.168.1.1/samples/ruuvi/ruuvi

## Disabling certificate validation

When dealing with development servers which have TLS enabled, but does not have appropriate certificates, one can use option `--insecure`. Beware, that using this exposes you to rogue servers and MITM attacks.
