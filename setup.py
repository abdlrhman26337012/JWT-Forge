from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", "r") as f:
    requirements = [l.strip() for l in f if l.strip() and not l.startswith('#')]

setup(
    name="jwtforge",
    version="1.0.0",
    author="JWTForge",
    description="All-in-one JWT exploitation suite: none alg, key confusion, brute force, KID injection, JKU/X5U spoofing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/jwtforge",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "jwtforge=jwtforge.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
    ],
)
