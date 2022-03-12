import setuptools

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setuptools.setup(
    name="wgtool",
    version="1.1.5",
    author="rpcsp",
    author_email="pcunha@hotmail.com",
    description="WireGuard Configuration Tool",
    license="https://github.com/rpcsp/wgtool/blob/main/LICENSE",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rpcsp/wgtool",
    project_urls={
        "Project page": "https://github.com/rpcsp/wgtool",
    },
    classifiers=[
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.7",
    entry_points="""\
    [console_scripts]
    wgtool = wgtool.cli:main
    """,
)
