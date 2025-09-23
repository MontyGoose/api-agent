def test_list_items_requires_auth(client):
    r = client.get("/api/v1/items/")
    assert r.status_code in (401, 403)


def test_list_items_with_token(client, user_token, auth_header):
    r = client.get("/api/v1/items/", headers=auth_header(user_token))
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    assert any(item["name"] == "widget" for item in data)


def test_get_item_found(client, user_token, auth_header):
    r = client.get("/api/v1/items/1", headers=auth_header(user_token))
    assert r.status_code == 200
    assert r.json()["id"] == 1


def test_get_item_not_found(client, user_token, auth_header):
    r = client.get("/api/v1/items/999", headers=auth_header(user_token))
    assert r.status_code == 200
    assert r.json().get("error") == "not found"


def test_create_item_requires_admin(client, user_token, auth_header):
    r = client.post("/api/v1/items/", json={"name": "thing"}, headers=auth_header(user_token))
    assert r.status_code == 403


def test_create_item_admin_ok(client, admin_token, auth_header):
    r = client.post("/api/v1/items/", json={"name": "thing"}, headers=auth_header(admin_token))
    assert r.status_code == 200
    body = r.json()
    assert body["id"] >= 1
    assert body["name"] == "thing"


