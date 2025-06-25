# 🦆 QuackCrack

![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/yourusername/quackcrack?style=flat-square)
![Python Version](https://img.shields.io/badge/python-3.7%2B-blue?style=flat-square)
![License](https://img.shields.io/github/license/ducksex/quackcrack?style=flat-square)
![Build Status](https://img.shields.io/github/actions/workflow/status/yourusername/quackcrack/python.yml?branch=main&style=flat-square)

---

> **QuackCrack** is your 🦆 **go-to terminal tool** for instantly cracking encoded or lightly encrypted strings — automatically guessing and applying multiple decoding methods to speed up your pentest workflow.

---

## ✨ Why QuackCrack?

As a pentester or security analyst, you often stumble on mysterious strings encoded or encrypted in unknown ways.  
**QuackCrack** automates the tedious guesswork by running a suite of decoding & decryption techniques —  
so you can focus on what really matters: cracking the case.

---

## ⚡ Features at a Glance

| 🧰 Decoding Techniques      | 🎯 Highlights                      |
| -------------------------- | --------------------------------- |
| Base64 (standard & URL-safe) | Validates padding & format         |
| Hexadecimal (with spaces allowed) | Auto-handles casing and spacing  |
| ROT13                      | Classic simple cipher support      |
| URL Percent-decoding       | Decode URL-encoded strings         |
| XOR Single-byte brute-force| Tries all 256 keys, top printable results |

---

## 🦆 QuackCrack in Action

```bash
$ quackcrack
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⠿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
...
Welcome to QuackCrack
Enter your suspicious data (encoded/encrypted). Type 'exit' to quit.

Data to analyze > Uryyb jbeyq!
==> Method: ROT13
Hello world!

----------------------------------------
Data to analyze > SGVsbG8gd29ybGQh
==> Method: Base64
Hello world!

----------------------------------------
Data to analyze > exit
Goodbye! 🦆
```
##🚀 Installation Guide
##Requirements

    Python 3.7 or higher

    pip package manager

##Windows

    Install Python 3.7+
    Download and install from python.org.
    Make sure to check “Add Python to PATH” during installation.

    Open Command Prompt (Win + R, type cmd, Enter)

    Clone and install QuackCrack

git clone https://github.com/yourusername/quackcrack.git
cd quackcrack
pip install .

    Run QuackCrack

quackcrack

##macOS

    Install Python 3.7+
    macOS usually ships with Python 2.x, so install Python 3 with Homebrew:

brew install python

    Open Terminal

    Clone and install QuackCrack

git clone https://github.com/yourusername/quackcrack.git
cd quackcrack
pip3 install .

    Run QuackCrack

quackcrack

##Linux (Ubuntu/Debian)

    Install Python 3.7+ and pip

sudo apt update
sudo apt install python3 python3-pip git -y

    Clone and install QuackCrack

git clone https://github.com/yourusername/quackcrack.git
cd quackcrack
pip3 install .

    Run QuackCrack

quackcrack

##🛠 Troubleshooting

    'quackcrack' is not recognized or command not found error:
    Try running Python module directly:

python -m quackcrack.cli
# or on Linux/macOS
python3 -m quackcrack.cli

    Permission errors during install:
    Try adding --user flag to pip:

pip install --user .

    Git not installed?
    Install Git from git-scm.com or your OS package manager.

##🏗️ Project Structure

quackcrack/
├── cli.py          # Terminal UI & main entry point
├── decoders.py     # Decoding & brute force logic
├── utils.py        # Helper utilities (printable text check)
└── __init__.py     # Package initializer

setup.py            # Installation & packaging
tests/              # Unit tests
README.md           # This stylish documentation

##🧑‍💻 Contributing

Bug reports, feature requests, and pull requests are welcome!
Please adhere to clean code practices and include tests.


