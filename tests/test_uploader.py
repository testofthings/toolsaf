import pytest
from unittest.mock import patch
from pathlib import Path
import tempfile

from toolsaf.core.uploader import Uploader
from toolsaf.main import ConfigurationException


@pytest.mark.parametrize(
    "arg, exp",
    [
        (True, Path("/home/.toolsaf/.apikey")),
        ("/test/path/.apikey", Path("/test/path/.apikey"))
    ]
)
def test_get_key_file_path_based_on_argument(arg, exp):
    with patch.object(Path, "home") as mock_home:
        mock_home.return_value = Path("/home")
        uploader = Uploader(arg, "")
        assert uploader._get_key_file_path_based_on_argument() == exp

@pytest.mark.parametrize(
    "arg, key_content, exp_exception",
    [
        (True, "test_api_key", None),
        ("/test/path/.apikey", "another_test_api_key", None),
        ("/invalid/path/.apikey", None, ConfigurationException)
    ]
)
def test_read_api_key(arg, key_content, exp_exception):
    with patch.object(Path, "home") as mock_home, \
         patch.object(Path, "exists") as mock_exists, \
         patch.object(Path, "open", create=True) as mock_open:

        mock_home.return_value = Path("/home")
        uploader = Uploader(arg, "")

        if exp_exception:
            mock_exists.return_value = False
            with pytest.raises(exp_exception):
                uploader.read_api_key()
        else:
            mock_exists.return_value = True
            mock_open.return_value.__enter__.return_value.read.return_value = key_content
            uploader.read_api_key()
            assert uploader._api_key == key_content





