# SIMULATION: harmless encoded content for scanner testing.
# Decodes to a print() statement only. No credentials, no network.
import base64

BLOB = "cHJpbnQoJ1NJTVVMQVRJT046IGhhcm1sZXNzIGRlY29kZWQgdGV4dCB1c2VkIG9ubHkgZm9yIHNjYW5uZXIgdGVzdGluZycp"


def run() -> None:
    exec(base64.b64decode(BLOB).decode("utf-8"))
