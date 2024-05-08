import setuptools

with open("README.md", "r") as file:
    readme = file.read()

setuptools.setup(
    name="pychacha",
    version="1.0.2",
    description="ChaCha20 encryption tools for Python.",
    url="https://github.com/thecodeforge/pychacha",
    py_modules=["pychacha"],
    install_requires=[],
    packages=setuptools.find_packages(),
    package_dir={
        "pychacha":"pychacha"
    },
    python_requires= '>=3.11',
    long_description = readme,
    long_description_content_type = "text/markdown"
)