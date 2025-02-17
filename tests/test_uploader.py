import pytest
import sys
from unittest.mock import patch, MagicMock
from pathlib import Path
import tempfile

from toolsaf.core.uploader import Uploader
from toolsaf.main import ConfigurationException


@pytest.mark.parametrize(
    "dir_exists",
    [True, False]
)
def test_create_directory(dir_exists):
    with patch.object(Path, "exists") as mock_exists, \
         patch.object(Path, "mkdir") as mock_mkdir:

        mock_exists.return_value = dir_exists
        Uploader("")._create_directory(Path())
        if dir_exists:
            mock_mkdir.assert_not_called()
        else:
            mock_mkdir.assert_called_once()


def test_add_toolsaf_directory_to_home():
    uploader = Uploader("")
    uploader._toolsaf_home_dir = Path("test")
    uploader._create_directory = MagicMock()
    uploader._add_toolsaf_directory_to_home()
    uploader._create_directory.assert_called_once_with(Path("test"))


@pytest.mark.parametrize(
    "dir_exists",
    [True, False]
)
def test_add_directory_for_current_statement(dir_exists):
    with patch.object(sys, "path", ["home/directories/statement"]):
        uploader = Uploader("")
        uploader._toolsaf_home_dir = Path("test")
        uploader._create_directory = MagicMock()
        uploader._add_directory_for_current_statement()
        uploader._create_directory.assert_called_once_with(Path("test/statement"))


def test_get_key_file_path_based_on_argument():
    with patch.object(Path, "home") as mock_home:
        mock_home.return_value = Path("/home")
        uploader = Uploader("")
        uploader._toolsaf_home_dir = Path.home() / ".toolsaf"
        assert uploader._get_key_file_path_based_on_argument(True) == Path("/home/.toolsaf/.apikey")
        uploader = Uploader("/test/path/.apikey")
        assert uploader._get_key_file_path_based_on_argument("/test/path/.apikey") == Path("/test/path/.apikey")


def test_read_api_key():
    uploader = Uploader("")
    with patch.object(Path, "exists") as mock_exists:
        mock_exists.return_value = False
        with pytest.raises(ConfigurationException):
            uploader._read_api_key(Path())

        mock_exists.return_value = True
        with tempfile.NamedTemporaryFile() as tmp:
            with pytest.raises(ConfigurationException):
                uploader._read_api_key(Path(tmp.name))
            with open(tmp.name, "w") as f:
                f.write("test")
            uploader._read_api_key(Path(tmp.name))
            assert uploader._api_key == "test"


def test_headers():
    uploader = Uploader("")
    uploader._api_key = "test"
    assert uploader._headers == {
        "Authorization": "test",
        "Content-Type": "application/json"
    }


def test_post_success():
    uploader = Uploader("")
    uploader._api_key = "test"
    url = "https://127.0.0.1/api/test"
    data = {"key": "value"}

    with patch("requests.post") as mock_post:
        mock_response = mock_post.return_value
        mock_response.status_code = 200
        mock_response.json.return_value = {"test": "test"}

        response = uploader._post(url, data)
        mock_post.assert_called_once_with(url, json=data, headers=uploader._headers, verify=False, timeout=60)
        assert response.status_code == 200
        assert response.json() == {"test": "test"}


def test_post_failure():
    uploader = Uploader("")
    uploader._api_key = "test"
    url = "https://127.0.0.1/api/test"
    data = {"key": "value"}

    with patch("requests.post") as mock_post:
        mock_post.side_effect = ConnectionError("Failed to connect")

        with pytest.raises(ConnectionError, match="Data upload failed!"):
            uploader._post(url, data)
        mock_post.assert_called_once_with(url, json=data, headers=uploader._headers, verify=False, timeout=60)
