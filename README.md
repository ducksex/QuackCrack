# 🦆 QuackCrack

![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/ducksex/quackcrack?style=flat-square)
![Python Version](https://img.shields.io/badge/python-3.7%2B-blue?style=flat-square)
![License](https://img.shields.io/github/license/ducksex/quackcrack?style=flat-square)
![Build Status](https://img.shields.io/github/actions/workflow/status/ducksex/quackcrack/python.yml?branch=main&style=flat-square)

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
## 🚀 Installation Guide

# Requirements

    Python 3.7 or higher

    pip package manager

## Linux (Ubuntu/Debian)

# 1. Installer Python 3.7+ et pip
```bash
sudo apt update
sudo apt install python3 python3-pip git -y
```

# 2. Cloner le dépôt QuackCrack
```bash
git clone https://github.com/ducksex/quackcrack.git
cd quackcrack
```

# 3. Lancer QuackCrack
```bash
python3 start.py
```

## 🏗️ Project Structure
```bash
quackcrack/
├── cli.py          # Terminal UI & main entry point
├── decoders.py     # Decoding & brute force logic
├── utils.py        # Helper utilities (printable text check)
└── __init__.py     # Package initializer

setup.py            # Installation & packaging
README.md           # This stylish documentation
```

## 🧑‍💻 Contributing

Bug reports, feature requests, and pull requests are welcome!
Please adhere to clean code practices and include tests.

## 💌 Contact & Support

Made with ❤️ by DuckSex


