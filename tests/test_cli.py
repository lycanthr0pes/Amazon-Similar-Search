import argparse

import pytest

from src.main.run import positive_int


def test_positive_int_accepts_positive_value():
    assert positive_int("5") == 5


@pytest.mark.parametrize("value", ["0", "-1"])
def test_positive_int_rejects_non_positive_value(value):
    with pytest.raises(argparse.ArgumentTypeError):
        positive_int(value)
