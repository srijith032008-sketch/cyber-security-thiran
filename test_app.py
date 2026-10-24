import os
import re
import tempfile

os.environ["DB_FILE"] = os.path.join(tempfile.mkdtemp(), "t.db")

import pyotp
from app import app, init_db

init_db()
app.config["TESTING"] = True


def token(client, path):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def post(client, path, data, page=None):
    data["csrf_token"] = token(client, page or path)
    return client.post(path, data=data)


c = app.test_client()
r = post(c, "/register", {"username": "joseph", "email": "j@example.com", "password": "weak", "confirm": "weak"})
assert r.status_code == 400
r = post(c, "/register", {"username": "joseph", "email": "j@example.com", "password": "Str0ng!Passw0rd", "confirm": "Str0ng!Passw0rd"})
assert r.status_code == 302
r = post(c, "/register", {"username": "joseph", "email": "j2@example.com", "password": "Str0ng!Passw0rd", "confirm": "Str0ng!Passw0rd"})
assert r.status_code == 400
r = post(c, "/login", {"username": "joseph' OR '1'='1", "password": "x"})
assert r.status_code == 401
r = post(c, "/login", {"username": "joseph", "password": "wrong"})
assert r.status_code == 401
assert c.get("/dashboard").status_code == 302
assert c.post("/login", data={"username": "joseph", "password": "Str0ng!Passw0rd"}).status_code == 400
r = post(c, "/login", {"username": "joseph", "password": "Str0ng!Passw0rd"})
assert r.status_code == 302
assert b"Welcome, joseph" in c.get("/dashboard").data
c.get("/2fa/setup")
with c.session_transaction() as s:
    secret = s["totp_setup_secret"]
r = post(c, "/2fa/setup", {"code": pyotp.TOTP(secret).now()}, "/2fa/setup")
assert r.status_code == 302
post(c, "/logout", {}, "/dashboard")
assert c.get("/dashboard").status_code == 302
r = post(c, "/login", {"username": "joseph", "password": "Str0ng!Passw0rd"})
assert r.headers["Location"].endswith("/2fa/verify")
assert c.get("/dashboard").status_code == 302
r = post(c, "/2fa/verify", {"code": "000000"})
assert r.status_code == 401
r = post(c, "/2fa/verify", {"code": pyotp.TOTP(secret).now()})
assert r.status_code == 302
assert b"Welcome, joseph" in c.get("/dashboard").data

c2 = app.test_client()
for _ in range(5):
    post(c2, "/login", {"username": "joseph", "password": "bad"})
r = post(c2, "/login", {"username": "joseph", "password": "Str0ng!Passw0rd"})
assert r.status_code == 429
print("ALL TESTS PASSED")
