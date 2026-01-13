# Backward-compatible helpers (used by older code). Prefer app.core.security + app.core.jwt.

from app.core.security import hash_password, verify_password  # noqa: F401
from app.core.jwt import create_access_token  # noqa: F401
