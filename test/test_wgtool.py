import os
import sys


def test_importable():
    path = os.path.dirname(__file__)
    sys.path.insert(0, f"{path}/../src")

    import wgtool.cli  # noqa: F401
