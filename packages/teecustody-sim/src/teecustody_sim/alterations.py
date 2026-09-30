"""Token alterations used to produce negative cases."""

from dataclasses import dataclass

type JsonValue = bool | int | str | list[JsonValue] | dict[str, JsonValue] | None
type ClaimPath = tuple[str, ...]


@dataclass(frozen=True)
class AlterClaim:
    path: ClaimPath
    value: JsonValue


@dataclass(frozen=True)
class DropClaim:
    path: ClaimPath


@dataclass(frozen=True)
class NamedCase:
    case_id: str


type Alteration = AlterClaim | DropClaim | NamedCase
