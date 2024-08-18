
import sys
import os
from unittest import TestCase


class TestImportable(TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        path = os.path.dirname(__file__)
        sys.path.insert(0, f'{path}/../src')

    def test_importable(self):
        import wgtool.cli  # noqa: F401
