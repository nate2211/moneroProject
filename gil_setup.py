from setuptools import setup, Extension
import pybind11, sys

extra = ["/O2", "/std:c++17"] if sys.platform == "win32" else ["-O3", "-std=c++17"]

ext = Extension(
    "giltools",
    sources=["giltools.cpp"],
    include_dirs=[pybind11.get_include()],
    language="c++",
    extra_compile_args=extra,
)

setup(name="giltools", version="0.1.0", ext_modules=[ext])