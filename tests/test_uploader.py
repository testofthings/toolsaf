import pytest
import json
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
import tempfile

from toolsaf.core.uploader import Uploader
from toolsaf.core.model import IoTSystem
from toolsaf.main import ConfigurationException


SYSTEM = IoTSystem()
SYSTEM.upload_tag = "test"


def test_upload_tag_missing():
    system = IoTSystem()
    with pytest.raises(ConfigurationException):
        Uploader(system)


def test_do_upload_pre_procedures():
    uploader = Uploader(SYSTEM)
    uploader._add_toolsaf_directory_to_home = MagicMock()
    uploader._get_key_file_path_based_on_argument = MagicMock(return_value=Path("key_file"))
    uploader._read_api_url = MagicMock()
    uploader._read_api_key = MagicMock()

    uploader.do_upload_pre_procedures("key_file_arg")

    uploader._add_toolsaf_directory_to_home.assert_called_once()
    uploader._get_key_file_path_based_on_argument.assert_called_once_with("key_file_arg")
    uploader._read_api_url.assert_called_once()
    uploader._read_api_key.assert_called_once()


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


def test_read_api_url_file_not_exists():
    uploader = Uploader(SYSTEM)
    with patch.object(Path, "exists", return_value=False), \
         patch("builtins.input", return_value="api.test.com"), \
         patch("pathlib.Path.open", mock_open()) as mock_file:
        uploader._toolsaf_home_dir = Path("/tmp")
        uploader._read_api_url()
        mock_file.assert_called_with("w", encoding="utf-8")
        assert uploader._api_url == "https://api.test.com"


def test_read_api_url_file_exists():
    uploader = Uploader(SYSTEM)
    with patch.object(Path, "exists", return_value=True), \
         patch("pathlib.Path.open", mock_open(read_data="https://api.test.com")):
        uploader._toolsaf_home_dir = Path("/tmp")
        uploader._read_api_url()
        assert uploader._api_url == "https://api.test.com"


def test_read_api_url_file_exists_empty():
    uploader = Uploader(SYSTEM)
    with patch.object(Path, "exists", return_value=True), \
         patch("pathlib.Path.open", mock_open(read_data="")):
        uploader._toolsaf_home_dir = Path("/tmp")
        with pytest.raises(AssertionError):
            uploader._read_api_url()


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


def test_handle_response():
    uploader = Uploader(SYSTEM)
    mock_response = MagicMock()
    mock_response.ok = True
    mock_response.json.return_value = {"result": "success"}

    response_json = uploader._handle_response(mock_response, stop_on_error=True, print_response_json=True)
    assert response_json == {"result": "success"}


def test_handle_response_json_decode_error():
    uploader = Uploader(SYSTEM)
    mock_response = MagicMock()
    mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)

    with pytest.raises(ConnectionError):
        uploader._handle_response(mock_response)


def test_handle_response_no_json():
    uploader = Uploader(SYSTEM)
    mock_response = MagicMock()
    mock_response.json.return_value = None

    with pytest.raises(ConnectionError):
        uploader._handle_response(mock_response)


def test_handle_response_stop_on_error():
    uploader = Uploader(SYSTEM)
    mock_response = MagicMock()
    mock_response.ok = False
    mock_response.json.return_value = {"error": "Something went wrong"}

    with pytest.raises(ConnectionError):
        uploader._handle_response(mock_response, stop_on_error=True)


def test_upload_statement():
    uploader = Uploader(SYSTEM)
    uploader._api_url = "https://api.test.com"
    uploader.statement_name = "Test Statement"
    uploader.statement_url = "test-statement"

    with patch.object(uploader, "_post") as mock_post, \
         patch.object(uploader, "_handle_response") as mock_handle_response:

        assert uploader.upload_statement() is None
        mock_post.assert_called_once_with("https://api.test.com/api/statement",
                                          {"name": "Test Statement", "url": "test-statement"})
        mock_handle_response.assert_called_once()


def test_upload_system():
    uploader = Uploader(SYSTEM)
    uploader._api_url = "https://api.test.com"
    uploader.statement_url = "test-statement"
    entities = [{"id": 1}]

    with patch.object(uploader, "_post") as mock_post, \
         patch.object(uploader, "_handle_response") as mock_handle_response:

        assert uploader.upload_system(entities) is None
        mock_post.assert_called_once_with("https://api.test.com/api/statement/test-statement/entities", entities)
        mock_handle_response.assert_called_once()


def test_upload_evidence_source():
    uploader = Uploader(SYSTEM)
    uploader._api_url = "https://api.test.com"
    uploader.statement_url = "test-statement"
    source = {"type": "source"}

    with patch.object(uploader, "_post") as mock_post, \
         patch.object(uploader, "_handle_response") as mock_handle_response:

        mock_handle_response.return_value = {"source_id": "123"}

        source_id = uploader._upload_evidence_source(source)
        mock_post.assert_called_once_with("https://api.test.com/api/result/test-statement/evidence-source", source)
        mock_handle_response.assert_called_once()
        assert source_id == 123


def test_upload_evidence_source_no_source_id():
    uploader = Uploader(SYSTEM)
    uploader._api_url = "https://api.test.com"
    uploader.statement_url = "test-statement"
    source = {"type": "source"}

    with patch.object(uploader, "_post") as mock_post, \
         patch.object(uploader, "_handle_response") as mock_handle_response:

        mock_handle_response.return_value = {}
        with pytest.raises(ConnectionError):
            uploader._upload_evidence_source(source)


def test_upload_evidence_source_incorrect_source_id():
    uploader = Uploader(SYSTEM)
    uploader._api_url = "https://api.test.com"
    uploader.statement_url = "test-statement"
    source = {"type": "source"}

    with patch.object(uploader, "_post") as mock_post, \
         patch.object(uploader, "_handle_response") as mock_handle_response:

        mock_handle_response.return_value = {"source_id": "incorrect"}
        with pytest.raises(ConnectionError):
            uploader._upload_evidence_source(source)


def test_upload_events():
    uploader = Uploader(SYSTEM)
    uploader._api_url = "https://api.test.com"
    source_id = 123
    events = [{"type": "event"}]

    with patch.object(uploader, "_post") as mock_post, \
         patch.object(uploader, "_handle_response") as mock_handle_response:

        assert uploader._upload_events(events, source_id) is None
        mock_post.assert_called_once_with("https://api.test.com/api/result/evidence-source/123/events", events)
        mock_handle_response.assert_called_once()


def test_upload_logs():
    uploader = Uploader(SYSTEM)
    uploader._api_url = "https://api.test.com"
    uploader.statement_url = "test-statement"
    logs = [
        {"type": "source", "data": "source1"},
        {"type": "event", "data": "event1"},
        {"type": "event", "data": "event2"},
        {"type": "source", "data": "source2"},
        {"type": "event", "data": "event3"},
    ]

    with patch.object(uploader, "_upload_events") as mock_event_upload, \
         patch.object(uploader, "_upload_evidence_source") as mock_source_upload, \
         patch.object(uploader, "_post") as mock_post, \
         patch.object(uploader, "_handle_response") as mock_handle_response:

        mock_source_upload.side_effect = [1, 2]
        assert uploader.upload_logs(logs) is None
        assert mock_source_upload.call_count == 2
        mock_source_upload.assert_any_call(logs[0])
        mock_source_upload.assert_any_call(logs[3])

        assert mock_event_upload.call_count == 2
        mock_event_upload.assert_any_call([logs[1], logs[2]], 1)
        mock_event_upload.assert_any_call([logs[4]], 2)

        mock_post.assert_called_once_with("https://api.test.com/api/result/test-statement/commit", {})
        mock_handle_response.assert_called_once()
