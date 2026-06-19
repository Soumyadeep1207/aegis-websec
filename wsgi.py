"""Production WSGI entrypoint for hosted deployments."""

from app import create_app


app = create_app()
