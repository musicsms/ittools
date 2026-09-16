import ittools
import ittools.cli
import ittools.core


def test_package_metadata():
    assert ittools.__version__ == "0.2.0"


def test_package_modules():
    assert ittools.core is not None
    assert ittools.cli is not None
