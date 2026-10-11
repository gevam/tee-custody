# Negative fixture: neighbouring modules and the port the double implements are allowed.
import tests_helpers
from teecustody.channel.ports import ShareOpener
from teecustody.queue import ports


class StaticShareOpenerFactory:
    pass


DOUBLES = (tests_helpers, ShareOpener, ports, "tests.support")
