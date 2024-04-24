"""Command-line basic functions"""

import os
import pathlib
from typing import Dict

from aiohttp import web


API_KEY_NAME = "TCSFW_SERVER_API_KEY"

API_KEY_FILE_NAME = ".tcsfw_api_key"

def read_env_file() -> Dict[str, str]:
    """Read .env file"""
    values = {}
    env_file = pathlib.Path(".env")
    if env_file.exists():
        with env_file.open(encoding="utf-8") as f:
            for line in f:
                k, _, v = line.partition("=")
                if v is not None:
                    values[k.strip()] = v.strip()
    return values

def get_api_key() -> str:
    """Get API key from environment, key file or .env file"""
    key = os.environ.get(API_KEY_NAME, "").strip()
    if key:
        return key
    key_file = pathlib.Path(API_KEY_FILE_NAME)
    if key_file.exists():
        with key_file.open(encoding="utf-8") as f:
            return f.read().strip()
    values = read_env_file()
    return values.get(API_KEY_NAME, "")

def get_authorization(request: web.Request) -> str:
    """Get authorization from Web request"""
    auth_t = request.headers.get("x-authorization", "").strip()
    if not auth_t:
        auth_t = request.cookies.get("authorization", "").strip()
    return auth_t
