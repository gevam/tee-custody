# Positive fixture: suppression comments that would switch off the ruff bans (TID251).
# ruleid: tc-py-no-lint-suppression
# ruff: noqa
# ruleid: tc-py-no-lint-suppression
# ruff: noqa: TID251
# ruleid: tc-py-no-lint-suppression
# flake8: noqa
# ruleid: tc-py-no-lint-suppression
# ruff: disable[TID251]
# ruleid: tc-py-banned-import, tc-py-banned-import-sim, tc-py-no-lint-suppression, tc-py-gateway-banned-import, tc-py-gateway-dev-banned-import
import cbor2  # noqa: TID251
# ruleid: tc-py-no-lint-suppression
VALUE = cbor2  # noqa
# ruleid: tc-py-no-lint-suppression
OTHER = 1  #noqa
# ruleid: tc-py-no-lint-suppression
THIRD = 2  # NOQA E501
# ruleid: tc-py-no-lint-suppression
FOURTH = 3  # noqa: E501, tid252
# ruleid: tc-py-no-lint-suppression
FIFTH = 4  # nosec
# ruleid: tc-py-no-lint-suppression
SIXTH = 5  # nosec B105
# A7: formatter pragmas can hide a statement from review; banned over the rule's paths.
# ruleid: tc-py-no-lint-suppression
SEVENTH = 6  # fmt: skip
# ruleid: tc-py-no-lint-suppression
# fmt: off
# ruleid: tc-py-no-lint-suppression
# FMT:SKIP
