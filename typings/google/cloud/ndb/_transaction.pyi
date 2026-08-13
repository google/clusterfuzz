from typing import Any, Callable, Optional, TypeVar
from .tasklets import Future

_T = TypeVar('_T')

def in_transaction() -> bool: ...

def transaction(
    callback: Callable[..., _T],
    retries: int = ...,
    read_only: bool = ...,
    join: bool = ...,
    xg: bool = ...,
    propagation: Any = ...,
) -> _T: ...

def transaction_async(
    callback: Callable[..., _T],
    retries: int = ...,
    read_only: bool = ...,
    join: bool = ...,
    xg: bool = ...,
    propagation: Any = ...,
) -> Future[_T]: ...

def transactional(
    retries: int = ...,
    read_only: bool = ...,
    xg: bool = ...,
    propagation: Any = ...,
    join: bool = ...,
) -> Callable[[Callable[..., _T]], Callable[..., _T]]: ...

def transactional_async(
    retries: int = ...,
    read_only: bool = ...,
    xg: bool = ...,
    propagation: Any = ...,
    join: bool = ...,
) -> Callable[[Callable[..., _T]], Callable[..., _T]]: ...

def transactional_tasklet(
    retries: int = ...,
    read_only: bool = ...,
    xg: bool = ...,
    propagation: Any = ...,
    join: bool = ...,
) -> Callable[[Callable[..., _T]], Callable[..., _T]]: ...

def non_transactional(
    callback: Optional[Callable[..., _T]] = None,
) -> Any: ...
