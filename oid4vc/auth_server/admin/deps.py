"""Admin database session manager (no auth here)."""

from core.db.db import DatabaseSessionManager, make_session_dependency


db_manager = DatabaseSessionManager(search_path="admin")
get_db_session = make_session_dependency(db_manager)
