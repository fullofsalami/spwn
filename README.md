# Spwn

This repository is just the translation of [pwninit](https://github.com/io12/pwninit).
It has been created because I love the utilities provided by pwninit, but I'm to lazy to learn Rust and I wanted to customize it, so I rewrote it in python.

## Installation
```
sudo apt install elfutils
sudo apt install patchelf
pip install -r requirementes.txt
chmod +x spwn.py
sudo cp spwn.py /usr/bin/spwn
```
If you get errors with libarchive try following [this](https://stackoverflow.com/questions/29225812/libarchive-public-error-even-after-installing-libarchive-in-python) stackoverflow post.