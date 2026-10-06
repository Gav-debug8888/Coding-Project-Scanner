# install-hook-project (SIMULATION fixture)

JSON has no comments, so the `"//"` key in `package.json` carries the SIMULATION label.
The `postinstall` hook only echoes a string into `/tmp/scanner_test.txt`.
Expected finding: `PKG_INSTALL_SCRIPT` (HIGH).
