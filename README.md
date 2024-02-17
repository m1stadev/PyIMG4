<p align="center">
<img src=".github/assets/icon.png" alt="https://github.com/m1stadev/PyIMG4" width=256px> 
</p>

<h1 align="center">
PyIMG4
</h1>
<p align="center">
  <a href="https://github.com/m1stadev/PyIMG4/blob/master/LICENSE">
    <image src="https://img.shields.io/github/license/m1stadev/PyIMG4">
  </a>
  <a href="https://github.com/m1stadev/PyIMG4/stargazers">
    <image src="https://img.shields.io/github/stars/m1stadev/PyIMG4">
  </a>
  <a href="https://github.com/m1stadev/PyIMG4">
    <image src="https://tokei.rs/b1/github/m1stadev/PyIMG4?category=code&lang=python&style=flat">
  </a>
  <a href="https://github.com/m1stadev/PyIMG4">
    <image src="https://img.shields.io/github/actions/workflow/status/m1stadev/PyIMG4/.github/workflows/python-tests.yml">
  </a>
    <br>
</p>

<p align="center">
A Python library/CLI tool for parsing Apple's <a href="https://www.theiphonewiki.com/wiki/IMG4_File_Format">Image4 format</a>.
</p>

## Usage
```
Usage: pyimg4 [OPTIONS] COMMAND [ARGS]...

  A Python CLI tool for parsing Apple's Image4 format.

Options:
  --version  Show the version and exit.
  -h, --help     Show this message and exit.

Commands:
  im4m  Image4 manifest commands.
  im4p  Image4 payload commands.
  im4r  Image4 restore info commands.
  img4  Image4 commands.
```

## Requirements
- Python 3.8 or higher

## Installation
- Install from [PyPI](https://pypi.org/project/pyimg4/):
    - ```python3 -m pip install pyimg4```
    - If you would like to use the compression features of PyIMG4, install the optional libraries:
      - ```python3 -m pip install pyimg4[compression]```
- Local installation:
    - `./install.sh`
    - Requires [Poetry](https://python-poetry.org)

## Support

For any questions/issues you have, [open an issue](https://github.com/m1stadev/PyIMG4/issues) or join my [Discord](https://m1sta.xyz/discord).
