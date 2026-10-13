# Positive fixture: shipped code never reaches the test tree or its doubles (INC-2-API §5.2).
# ruleid: tc-py-no-test-doubles
import tests
# ruleid: tc-py-no-test-doubles
import tests.support.channel_doubles
# ruleid: tc-py-no-test-doubles
import os, tests.support as support
# ruleid: tc-py-no-test-doubles
from tests import support
# ruleid: tc-py-no-test-doubles
from tests.support.channel_doubles import StaticShareOpener as Opener


# ruleid: tc-py-no-test-doubles
class StaticShareOpener:
    pass


DOUBLES = (tests, support, os, Opener)
