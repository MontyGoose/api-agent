def test_hello_default(client):
    r = client.get("/api/v1/hello")
    assert r.status_code == 200
    assert r.json() == {"message": "hello, world!"}


def test_hello_name(client):
    r = client.get("/api/v1/hello", params={"name": "alice"})
    assert r.status_code == 200
    assert r.json() == {"message": "hello, alice!"}


