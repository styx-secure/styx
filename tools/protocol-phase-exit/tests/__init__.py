# Package marker so `python3 -m unittest discover -s tools/protocol-phase-exit`
# recurses into this directory and actually discovers test_verify.py.
# Without it the documented command reports "Ran 0 tests ... NO TESTS RAN" and
# exits 0, i.e. it passes vacuously. The explicit form
#   python3 -m unittest discover -s tools/protocol-phase-exit/tests -p 'test_*.py'
# worked because it starts inside the directory, but the documented
# repository-root command did not.
