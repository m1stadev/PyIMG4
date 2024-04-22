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
- Install from <a href="https://pypi.org/p/pyimg4">PyPI</a>:
    - ```python3 -m pip install pyimg4```
- Local installation:
    - `pip install --force-reinstall .`

## Notes
- For compression, LZFSE compression utilizes the <a href="https://pypi.org/p/apple-compress">apple-compress</a> library on *OS, and the <a href="https://pypi.org/p/lzfse">lzfse</a> library on all other OSes (due to libcompression not being available outside of Apple platforms).
  - If for some reason you'd like to force the lzfse library to be used on *OS (not recommended), you can set the environment variable `PYIMG4_FORCE_LZFSE`.

## Support
For any questions/issues you have, <a href="https://github.com/m1stadev/PyIMG4/issues">open an issue<a/>.
