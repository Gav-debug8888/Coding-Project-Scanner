# SIMULATION: harmless encoded content for scanner testing
# The blob below decodes to: print('hello from encoded script')
import base64

ENCODED = "cHJpbnQoJ2hlbGxvIGZyb20gZW5jb2RlZCBzY3JpcHQnKQ=="


def run() -> None:
    exec(base64.b64decode(ENCODED).decode("utf-8"))


if __name__ == "__main__":
    run()
