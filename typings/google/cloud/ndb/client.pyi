from typing import Any, Optional
from .context import Context

class Client:
    def __init__(
        self,
        project: Optional[str] = None,
        namespace: Optional[str] = None,
        database: Optional[str] = None,
        credentials: Optional[Any] = None,
        client_info: Optional[Any] = None,
        client_options: Optional[Any] = None,
    ) -> None: ...
    def context(
        self,
        namespace: Optional[str] = None,
        database: Optional[str] = None,
        global_cache: Optional[Any] = None,
        legacy_data: bool = True,
    ) -> Context: ...
