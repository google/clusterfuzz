import datetime
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    Iterable,
    Iterator,
    List,
    Literal,
    Optional,
    Sequence,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
    dataclass_transform,
    overload,
)

from .key import Key
from .query import FilterNode, PropertyOrder, Query

_T = TypeVar('_T')
_M = TypeVar('_M', bound='Model')

class Property(Generic[_T]):
    _name: str
    _code_name: str
    _indexed: bool
    _repeated: bool
    _required: bool
    _default: Any
    def __init__(
        self,
        name: Optional[str] = None,
        indexed: Optional[bool] = None,
        repeated: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
        write_empty_list: Optional[bool] = None,
    ) -> None: ...
    @overload
    def __get__(self: Property[_T], instance: None, owner: Any) -> Property[_T]: ...
    @overload
    def __get__(self: Property[_T], instance: Any, owner: Any) -> _T: ...
    def __set__(self, instance: Any, value: _T) -> None: ...
    def __delete__(self, instance: Any) -> None: ...
    def __eq__(self, other: Any) -> FilterNode: ...  # type: ignore[override]
    def __ne__(self, other: Any) -> FilterNode: ...  # type: ignore[override]
    def __lt__(self, other: Any) -> FilterNode: ...
    def __le__(self, other: Any) -> FilterNode: ...
    def __gt__(self, other: Any) -> FilterNode: ...
    def __ge__(self, other: Any) -> FilterNode: ...
    def IN(self, values: Iterable[Any]) -> FilterNode: ...
    def __neg__(self) -> PropertyOrder: ...
    def __pos__(self) -> PropertyOrder: ...

class StringProperty(Property[Any]):
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        *,
        repeated: Literal[True],
        indexed: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
        write_empty_list: Optional[bool] = None,
    ) -> Property[List[str]]: ...
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        indexed: Optional[bool] = None,
        repeated: Optional[Literal[False]] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
        write_empty_list: Optional[bool] = None,
    ) -> Property[Optional[str]]: ...
    @overload
    def __new__(cls, *args: Any, **kwargs: Any) -> Property[Any]: ...

class TextProperty(Property[Any]):
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        *,
        repeated: Literal[True],
        compressed: bool = False,
        indexed: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
        write_empty_list: Optional[bool] = None,
    ) -> Property[List[str]]: ...
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        compressed: bool = False,
        indexed: Optional[bool] = None,
        repeated: Optional[Literal[False]] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
        write_empty_list: Optional[bool] = None,
    ) -> Property[Optional[str]]: ...
    @overload
    def __new__(cls, *args: Any, **kwargs: Any) -> Property[Any]: ...

class IntegerProperty(Property[Any]):
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        *,
        repeated: Literal[True],
        indexed: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
        write_empty_list: Optional[bool] = None,
    ) -> Property[List[int]]: ...
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        indexed: Optional[bool] = None,
        repeated: Optional[Literal[False]] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
        write_empty_list: Optional[bool] = None,
    ) -> Property[Optional[int]]: ...
    @overload
    def __new__(cls, *args: Any, **kwargs: Any) -> Property[Any]: ...

class FloatProperty(Property[Any]):
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        *,
        repeated: Literal[True],
        indexed: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
        write_empty_list: Optional[bool] = None,
    ) -> Property[List[float]]: ...
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        indexed: Optional[bool] = None,
        repeated: Optional[Literal[False]] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
        write_empty_list: Optional[bool] = None,
    ) -> Property[Optional[float]]: ...
    @overload
    def __new__(cls, *args: Any, **kwargs: Any) -> Property[Any]: ...

class BooleanProperty(Property[Any]):
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        *,
        repeated: Literal[True],
        indexed: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
        write_empty_list: Optional[bool] = None,
    ) -> Property[List[bool]]: ...
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        indexed: Optional[bool] = None,
        repeated: Optional[Literal[False]] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
        write_empty_list: Optional[bool] = None,
    ) -> Property[Optional[bool]]: ...
    @overload
    def __new__(cls, *args: Any, **kwargs: Any) -> Property[Any]: ...

class DateTimeProperty(Property[Any]):
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        *,
        repeated: Literal[True],
        auto_now: bool = False,
        auto_now_add: bool = False,
        indexed: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
        tzinfo: Optional[datetime.tzinfo] = None,
    ) -> Property[List[datetime.datetime]]: ...
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        auto_now: bool = False,
        auto_now_add: bool = False,
        indexed: Optional[bool] = None,
        repeated: Optional[Literal[False]] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
        tzinfo: Optional[datetime.tzinfo] = None,
    ) -> Property[Optional[datetime.datetime]]: ...
    @overload
    def __new__(cls, *args: Any, **kwargs: Any) -> Property[Any]: ...

class DateProperty(Property[Any]):
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        *,
        repeated: Literal[True],
        auto_now: bool = False,
        auto_now_add: bool = False,
        indexed: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
    ) -> Property[List[datetime.date]]: ...
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        auto_now: bool = False,
        auto_now_add: bool = False,
        indexed: Optional[bool] = None,
        repeated: Optional[Literal[False]] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
    ) -> Property[Optional[datetime.date]]: ...
    @overload
    def __new__(cls, *args: Any, **kwargs: Any) -> Property[Any]: ...

class TimeProperty(Property[Any]):
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        *,
        repeated: Literal[True],
        auto_now: bool = False,
        auto_now_add: bool = False,
        indexed: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
    ) -> Property[List[datetime.time]]: ...
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        auto_now: bool = False,
        auto_now_add: bool = False,
        indexed: Optional[bool] = None,
        repeated: Optional[Literal[False]] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
    ) -> Property[Optional[datetime.time]]: ...
    @overload
    def __new__(cls, *args: Any, **kwargs: Any) -> Property[Any]: ...

class JsonProperty(Property[Any]):
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        *,
        repeated: Literal[True],
        compressed: bool = False,
        json_type: Optional[Type[Any]] = None,
        indexed: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
    ) -> Property[List[Any]]: ...
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        compressed: bool = False,
        json_type: Optional[Type[Any]] = None,
        indexed: Optional[bool] = None,
        repeated: Optional[Literal[False]] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
    ) -> Property[Any]: ...
    @overload
    def __new__(cls, *args: Any, **kwargs: Any) -> Property[Any]: ...

class PickleProperty(Property[Any]):
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        *,
        repeated: Literal[True],
        compressed: bool = False,
        indexed: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
    ) -> Property[List[Any]]: ...
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        compressed: bool = False,
        indexed: Optional[bool] = None,
        repeated: Optional[Literal[False]] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
    ) -> Property[Any]: ...
    @overload
    def __new__(cls, *args: Any, **kwargs: Any) -> Property[Any]: ...

class BlobProperty(Property[Any]):
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        *,
        repeated: Literal[True],
        compressed: bool = False,
        indexed: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
    ) -> Property[List[bytes]]: ...
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        compressed: bool = False,
        indexed: Optional[bool] = None,
        repeated: Optional[Literal[False]] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
    ) -> Property[Optional[bytes]]: ...
    @overload
    def __new__(cls, *args: Any, **kwargs: Any) -> Property[Any]: ...

class BlobKeyProperty(Property[Any]):
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        *,
        repeated: Literal[True],
        indexed: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
    ) -> Property[List[str]]: ...
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        indexed: Optional[bool] = None,
        repeated: Optional[Literal[False]] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
    ) -> Property[Optional[str]]: ...
    @overload
    def __new__(cls, *args: Any, **kwargs: Any) -> Property[Any]: ...

class GenericProperty(Property[Any]):
    def __init__(
        self,
        name: Optional[str] = None,
        indexed: Optional[bool] = None,
        repeated: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
    ) -> None: ...

class GeoPtProperty(Property[Any]):
    def __init__(
        self,
        name: Optional[str] = None,
        indexed: Optional[bool] = None,
        repeated: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
    ) -> None: ...

class UserProperty(Property[Any]):
    def __init__(
        self,
        name: Optional[str] = None,
        auto_current_user: bool = False,
        auto_current_user_add: bool = False,
        indexed: Optional[bool] = None,
        repeated: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
    ) -> None: ...

class KeyProperty(Property[Any]):
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        *,
        repeated: Literal[True],
        kind: Optional[Union[str, Type['Model']]] = None,
        indexed: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
    ) -> Property[List[Key]]: ...
    @overload
    def __new__(
        cls,
        name: Optional[str] = None,
        kind: Optional[Union[str, Type['Model']]] = None,
        indexed: Optional[bool] = None,
        repeated: Optional[Literal[False]] = None,
        required: Optional[bool] = None,
        default: Any = None,
        choices: Optional[Iterable[Any]] = None,
        validator: Optional[Callable[[Any, Any], Any]] = None,
        verbose_name: Optional[str] = None,
    ) -> Property[Optional[Key]]: ...
    @overload
    def __new__(cls, *args: Any, **kwargs: Any) -> Property[Any]: ...

class ComputedProperty(Property[_T]):
    def __init__(
        self,
        func: Callable[[Any], _T],
        name: Optional[str] = None,
        indexed: Optional[bool] = None,
        repeated: Optional[bool] = None,
        verbose_name: Optional[str] = None,
    ) -> None: ...

class StructuredProperty(Property[Any]):
    @overload
    def __new__(
        cls,
        modelclass: Type[_M],
        name: Optional[str] = None,
        *,
        repeated: Literal[True],
        indexed: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
    ) -> Property[List[_M]]: ...
    @overload
    def __new__(
        cls,
        modelclass: Type[_M],
        name: Optional[str] = None,
        indexed: Optional[bool] = None,
        repeated: Optional[Literal[False]] = None,
        required: Optional[bool] = None,
        default: Any = None,
    ) -> Property[Optional[_M]]: ...
    @overload
    def __new__(cls, *args: Any, **kwargs: Any) -> Property[Any]: ...

class LocalStructuredProperty(StructuredProperty):
    @overload
    def __new__(
        cls,
        modelclass: Type[_M],
        name: Optional[str] = None,
        *,
        repeated: Literal[True],
        compressed: bool = False,
        indexed: Optional[bool] = None,
        required: Optional[bool] = None,
        default: Any = None,
    ) -> Property[List[_M]]: ...
    @overload
    def __new__(
        cls,
        modelclass: Type[_M],
        name: Optional[str] = None,
        compressed: bool = False,
        indexed: Optional[bool] = None,
        repeated: Optional[Literal[False]] = None,
        required: Optional[bool] = None,
        default: Any = None,
    ) -> Property[Optional[_M]]: ...
    @overload
    def __new__(cls, *args: Any, **kwargs: Any) -> Property[Any]: ...

class ModelAdapter: ...
class ModelAttribute: ...
class ModelKey(Key): ...

class MetaModel(type): ...

class Model(metaclass=MetaModel):
    key: Key
    _kind_map: Dict[str, Type['Model']]
    _properties: Dict[str, Property[Any]]
    _use_cache: bool
    _use_memcache: bool
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
    @classmethod
    def query(cls: Type[_M], *args: Any, **kwargs: Any) -> Query[_M]: ...
    @classmethod
    def gql(cls: Type[_M], query_string: str, *args: Any, **kwds: Any) -> Query[_M]: ...
    @classmethod
    def get_by_id(cls: Type[_M], id: Union[int, str], parent: Optional[Key] = None, **kwargs: Any) -> Optional[_M]: ...
    @classmethod
    def get_by_id_async(cls: Type[_M], id: Union[int, str], parent: Optional[Key] = None, **kwargs: Any) -> Any: ...
    @classmethod
    def get_or_insert(cls: Type[_M], name: str, parent: Optional[Key] = None, **kwargs: Any) -> _M: ...
    @classmethod
    def get_or_insert_async(cls: Type[_M], name: str, parent: Optional[Key] = None, **kwargs: Any) -> Any: ...
    @classmethod
    def _get_kind(cls) -> str: ...
    def put(self, **kwargs: Any) -> Key: ...
    def put_async(self, **kwargs: Any) -> Any: ...
    def to_dict(self, include: Optional[Sequence[str]] = None, exclude: Optional[Sequence[str]] = None) -> Dict[str, Any]: ...
    def populate(self, **kwargs: Any) -> None: ...
    def _pre_put_hook(self) -> None: ...
    def _post_put_hook(self, future: Any) -> None: ...
    @classmethod
    def _pre_delete_hook(cls, key: Key) -> None: ...
    @classmethod
    def _post_delete_hook(cls, key: Key, future: Any) -> None: ...

class Expando(Model): ...

class BlobKey:
    def __init__(self, blob_key: str) -> None: ...

class GeoPt:
    lat: float
    lon: float
    def __init__(self, lat: float, lon: float) -> None: ...

class User:
    def __init__(self, email: Optional[str] = None, _auth_domain: Optional[str] = None, _user_id: Optional[str] = None) -> None: ...
    def email(self) -> str: ...
    def nickname(self) -> str: ...
    def user_id(self) -> Optional[str]: ...

class Index: ...
class IndexProperty: ...
class IndexState: ...

def get_multi(keys: Sequence[Key], **kwargs: Any) -> List[Optional[Model]]: ...
def get_multi_async(keys: Sequence[Key], **kwargs: Any) -> Any: ...
def put_multi(entities: Sequence[Model], **kwargs: Any) -> List[Key]: ...
def put_multi_async(entities: Sequence[Model], **kwargs: Any) -> Any: ...
def delete_multi(keys: Sequence[Key], **kwargs: Any) -> List[None]: ...
def delete_multi_async(keys: Sequence[Key], **kwargs: Any) -> Any: ...
def get_indexes(**kwargs: Any) -> Any: ...
def get_indexes_async(**kwargs: Any) -> Any: ...
def make_connection(**kwargs: Any) -> Any: ...

class BadProjectionError(Exception): ...
class ComputedPropertyError(Exception): ...
class InvalidPropertyError(Exception): ...
class KindError(Exception): ...
class ReadonlyPropertyError(Exception): ...
class Rollback(Exception): ...
class UnprojectedPropertyError(Exception): ...
class UserNotFoundError(Exception): ...
