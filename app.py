"""Vercel entrypoint for the Aegis WebSec Flask application."""

from app import create_app


app = create_app()
