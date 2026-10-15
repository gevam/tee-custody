# Negative fixture: code-specific suppressions outside the TID family stay available.
TOKEN_REJECTED = "TOKEN_REJECTED"  # noqa: S105 - an error code
LONG = 1  # noqa: E501
BOTH = 2  # noqa: S105, E501
# type: ignore comments are mypy's, not ruff's.
NOSECURITY_NOTE = "nosec is not used in source"
# fmt: on
FORMAT_NOTE = "fmt: skip is not used in source"
