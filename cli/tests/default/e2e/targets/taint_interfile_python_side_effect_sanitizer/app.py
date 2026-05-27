from helpers import clean
from source import get_input


def main():
    data = get_input()
    clean(data)
    sink(data)
    unsafe = get_input()
    sink(unsafe)
