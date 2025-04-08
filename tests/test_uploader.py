import pytest
import sys
from unittest.mock import patch, MagicMock
from pathlib import Path
import tempfile

from toolsaf.core.uploader import Uploader
from toolsaf.core.model import IoTSystem
from toolsaf.main import ConfigurationException


SYSTEM = IoTSystem()
SYSTEM.upload_tag = "test"


@pytest.mark.parametrize(
    "dir_exists",
    [True, False]
)
def test_create_directory(dir_exists):
    with patch.object(Path, "exists") as mock_exists, \
         patch.object(Path, "mkdir") as mock_mkdir:

        mock_exists.return_value = dir_exists
        Uploader(SYSTEM)._create_directory(Path())
        if dir_exists:
            mock_mkdir.assert_not_called()
        else:
            mock_mkdir.assert_called_once()


def test_add_toolsaf_directory_to_home():
    uploader = Uploader(SYSTEM)
    uploader._toolsaf_home_dir = Path("test")
    uploader._create_directory = MagicMock()
    uploader._add_toolsaf_directory_to_home()
    uploader._create_directory.assert_called_once_with(Path("test"))


def test_get_key_file_path_based_on_argument():
    with patch.object(Path, "home") as mock_home:
        mock_home.return_value = Path("/home")
        uploader = Uploader(SYSTEM)
        uploader._toolsaf_home_dir = Path.home() / ".toolsaf"
        assert uploader._get_key_file_path_based_on_argument(None) == Path("/home/.toolsaf/.api_key")
        uploader = Uploader(SYSTEM)
        assert uploader._get_key_file_path_based_on_argument("/test/path/.api_key") == Path("/test/path/.api_key")


def test_read_api_key():
    uploader = Uploader(SYSTEM)
    with patch.object(Path, "exists") as mock_exists:
        mock_exists.return_value = False
        uploader._key_file_path = "fake/path"
        with pytest.raises(ConfigurationException):
            uploader._read_api_key()

        mock_exists.return_value = True
        with tempfile.NamedTemporaryFile() as tmp:
            with pytest.raises(ConfigurationException):
                uploader._key_file_path = Path(tmp.name)
                uploader._read_api_key()
            with open(tmp.name, "w") as f:
                f.write("test")
            uploader._key_file_path = Path(tmp.name)
            uploader._read_api_key()
            assert uploader._api_key == "test"


def test_headers():
    uploader = Uploader(SYSTEM)
    uploader._api_key = "test"
    assert uploader._headers == {
        "Authorization": "test",
        "Content-Type": "application/json"
    }


def test_post_success():
    uploader = Uploader(SYSTEM)
    uploader._api_key = "test"
    url = "https://127.0.0.1/api/test"
    data = {"key": "value"}

    with patch("requests.post") as mock_post:
        mock_response = mock_post.return_value
        mock_response.status_code = 200
        mock_response.json.return_value = {"test": "test"}

        response = uploader._post(url, data)
        mock_post.assert_called_once_with(url, json=data, headers=uploader._headers, verify=True, timeout=60)
        assert response.status_code == 200
        assert response.json() == {"test": "test"}

        uploader.allow_insecure = True
        response = uploader._post(url, data)
        mock_post.assert_called_with(url, json=data, headers=uploader._headers, verify=False, timeout=60)


def test_post_failure():
    uploader = Uploader(SYSTEM)
    uploader._api_key = "test"
    url = "https://127.0.0.1/api/test"
    data = {"key": "value"}

    with patch("requests.post") as mock_post:
        mock_post.side_effect = ConnectionError("Failed to connect")

        with pytest.raises(ConnectionError, match="Data upload failed!"):
            uploader._post(url, data)
        mock_post.assert_called_once_with(url, json=data, headers=uploader._headers, verify=True, timeout=60)
