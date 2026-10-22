# Verification

Test sources remain in ../tests. This directory holds generated reports and synthetic databases.
Run from project root: dev/.venv/Scripts/python.exe -m pytest --basetemp=test/pytest-temp --junitxml=test/pytest.xml
Portable verification: prod/FirewallCompliance/FirewallCompliance.exe --self-test test/packaged-smoke
