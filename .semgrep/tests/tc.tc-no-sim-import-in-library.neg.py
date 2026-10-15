# Negative fixture: tests may name the simulator in strings to assert its absence.
# ruleid: tc-py-gateway-banned-import
import teecustody

FORBIDDEN = ("teecustody_sim", "teecustody-sim", "import teecustody_sim")
assert "teecustody_sim" not in dir(teecustody)
