# multi-warning-project (SIMULATION fixture)

Combines several weak signals the way a fake-recruiter "assignment" might:
postinstall hook + VS Code folderOpen task + base64/exec loader + an SSH key
path string + a `requests.get` call in `setup.py`.

Every item is inert: the key path is never opened, the network helper is never
called and targets the unresolvable `example.invalid` domain, and the encoded
blob decodes to a `print()` statement.

Expected overall risk level: **CRITICAL** (composite rule).
