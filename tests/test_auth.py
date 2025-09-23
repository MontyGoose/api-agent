def test_login_returns_token(client):
    r = client.post("/api/v1/auth/token", data={"username": "user", "password": "x"})
    assert r.status_code == 200
    body = r.json()
    assert "access_token" in body
    assert body.get("token_type") == "bearer"


