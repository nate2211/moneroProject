from setuptools import setup, Extension
import sys

# The pybind11 module must be installed before this script is run
try:
    import pybind11
except ImportError:
    raise RuntimeError("pybind11 is not installed. Please run 'pip install pybind11'.")

# Set compiler flags based on the operating system
extra_compile_args = ["/O2", "/std:c++17"] if sys.platform == "win32" else ["-O3", "-std=c++17"]

ext = Extension(
    "giltools",
    sources=["giltools.cpp"],
    include_dirs=[pybind11.get_include()],
    language="c++",
    extra_compile_args=extra_compile_args,
)

setup(
    name="giltools",
    version="0.1.0",
    description="GIL helpers and CPU boosting tools.",
    ext_modules=[ext],
    # This is a better way to handle dependencies, but 'setup_requires'
    # is often necessary for build time dependencies like pybind11.
    setup_requires=["pybind11>=2.6.0"],
)