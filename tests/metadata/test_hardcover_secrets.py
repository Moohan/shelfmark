from unittest.mock import patch, mock_open
import os
from shelfmark.metadata_providers.hardcover import _normalize_hardcover_api_key

def test_normalize_hardcover_api_key_with_plain_token():
    token = "this-is-a-very-long-token-that-should-be-at-least-one-hundred-characters-long-to-pass-validation-checks-if-any"
    assert _normalize_hardcover_api_key(token) == token

def test_normalize_hardcover_api_key_with_bearer_prefix():
    token = "this-is-a-very-long-token-that-should-be-at-least-one-hundred-characters-long-to-pass-validation-checks-if-any"
    assert _normalize_hardcover_api_key(f"Bearer {token}") == token

def test_normalize_hardcover_api_key_with_secret_path():
    secret_path = "/run/secrets/hardcover_token"
    secret_content = "secret-token-from-file-that-is-also-very-long-and-should-be-read-correctly-from-the-filesystem-by-the-function"

    with patch("builtins.open", mock_open(read_data=secret_content)),          patch("os.path.isfile", return_value=True),          patch("os.path.realpath", side_effect=lambda x: os.path.normpath(x)):
        normalized = _normalize_hardcover_api_key(secret_path)
        assert normalized == secret_content

def test_normalize_hardcover_api_key_with_secret_path_and_bearer_in_file():
    secret_path = "/run/secrets/hardcover_token"
    token = "secret-token-from-file"
    secret_content = f"Bearer {token}"

    with patch("builtins.open", mock_open(read_data=secret_content)),          patch("os.path.isfile", return_value=True),          patch("os.path.realpath", side_effect=lambda x: os.path.normpath(x)):
        normalized = _normalize_hardcover_api_key(secret_path)
        assert normalized == token

def test_normalize_hardcover_api_key_with_unreadable_secret_path():
    secret_path = "/run/secrets/hardcover_token"

    with patch("builtins.open", side_effect=OSError("Read error")),          patch("os.path.isfile", return_value=True),          patch("os.path.realpath", side_effect=lambda x: os.path.normpath(x)),          patch("shelfmark.metadata_providers.hardcover.logger") as mock_logger:
        normalized = _normalize_hardcover_api_key(secret_path)
        assert normalized == ""
        mock_logger.warning.assert_called_with("Failed to read Hardcover API key from secret file: %s", secret_path)

def test_normalize_hardcover_api_key_with_missing_secret_path():
    secret_path = "/run/secrets/hardcover_token"

    with patch("os.path.isfile", return_value=False),          patch("os.path.realpath", side_effect=lambda x: os.path.normpath(x)),          patch("shelfmark.metadata_providers.hardcover.logger") as mock_logger:
        normalized = _normalize_hardcover_api_key(secret_path)
        assert normalized == ""
        mock_logger.warning.assert_called_with("Hardcover API key secret file not found: %s", secret_path)

def test_normalize_hardcover_api_key_with_path_traversal():
    secret_path = "/run/secrets/../../etc/passwd"

    # Simulate realpath returning a path outside of /run/secrets
    def mock_realpath(path):
        if "../../" in path:
             return "/etc/passwd"
        return os.path.normpath(path)

    with patch("os.path.realpath", side_effect=mock_realpath),          patch("shelfmark.metadata_providers.hardcover.logger") as mock_logger:
        normalized = _normalize_hardcover_api_key(secret_path)
        assert normalized == ""
        mock_logger.warning.assert_called_with("Hardcover API key path traversal attempt blocked: %s", secret_path)
