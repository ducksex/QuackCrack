from setuptools import setup, find_packages

setup(
    name='quackcrack',
    version='1.0.0',
    author='DuckSex',
    url='https://github.com/ducksex/quackcrack',
    packages=find_packages(),
    python_requires='>=3.7',
    entry_points={
        'console_scripts': [
            'quackcrack=quackcrack.cli:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
