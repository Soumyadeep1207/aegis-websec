from app.web import create_app


def test_index_loads(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "test.sqlite3")})
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert b"WebSec Scanner" in response.data
