from soc_analyzer.parser import get_username

def test_existing_user():
    message = "Failed password for Alice from 192.0.2.10 port 12321 ssh2"
    result = get_username(message)
    assert result == "Alice"

def test_invalid_user():
    message = "Failed password for invalid user soc_test_missing from 192.0.2.30 port 5000 ssh2"
    result2 = get_username(message)
    assert result2 == "soc_test_missing"

def test_unrelates_message():
    message = "Server listenin on 0.0.0.0 port 2222"
    result = get_username(message)
    assert result is None
