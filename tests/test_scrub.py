from rangefinder.capture.scrub import Scrubber


def s(text):
    return Scrubber().text(text)


def test_key_value_secrets():
    assert "hunter2" not in s("password=hunter2")
    assert "hunter2" not in s('{"api_key": "hunter2xyz"}')
    assert "hunter2" not in s("DB_PASSWORD: hunter2")
    assert "REDACTED" in s("password=hunter2")


def test_connection_string():
    out = s("Server=db;User Id=sa;Password=Sup3rSecret!;")
    assert "Sup3rSecret" not in out


def test_url_credentials():
    out = s("ldap://admin:s3cret@10.0.0.1/")
    assert "s3cret" not in out and "admin" not in out
    assert "10.0.0.1" in out  # host preserved


def test_provider_tokens_and_jwt():
    assert "AKIAIOSFODNN7EXAMPLE" not in s("aws_key AKIAIOSFODNN7EXAMPLE end")
    assert "ghp_" not in s("token ghp_0123456789abcdefghijklmnopqrstuvwxyz done")
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123_-"
    assert jwt not in s(f"Authorization: Bearer {jwt}")


def test_pem_private_key():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc123\nDEFghi456\n-----END RSA PRIVATE KEY-----"
    out = s(pem)
    assert "MIIEabc123" not in out
    assert "BEGIN PRIVATE KEY" in out  # structure marker kept


def test_pii_ssn_and_credit_card_luhn():
    assert "REDACTED" in s("SSN: 123-45-6789")
    # 4111 1111 1111 1111 is a valid Luhn test card -> redacted
    assert "4111" not in s("card 4111 1111 1111 1111")
    # a random 16-digit non-Luhn number is left alone (avoid false positives)
    assert "1234567812345678" in s("id 1234567812345678")


def test_email_pseudonymized_consistently():
    sc = Scrubber()
    out1 = sc.text("contact alice@corp.local for access")
    out2 = sc.text("owner: alice@corp.local")
    assert "alice@corp.local" not in out1
    fake = out1.split()[1]
    assert fake.endswith("@example.invalid")
    assert fake in out2  # same input -> same synthetic value across the capture


def test_high_entropy_token():
    assert "deadbeefdeadbeefdeadbeefdeadbeef01" not in s("hash deadbeefdeadbeefdeadbeefdeadbeef01")


def test_benign_text_untouched():
    text = "Welcome to ACME. See IT for access requests."
    assert s(text) == text
