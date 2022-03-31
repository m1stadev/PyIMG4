import argparse
import pyimg4


def main() -> None:
    parser = argparse.ArgumentParser(
        usage='pyimg4 [options]',
    )
    args = parser.parse_args()

    print(f'pyimg4 {pyimg4.__version__}')


if __name__ == '__main__':
    main()
