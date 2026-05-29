from helpers import Helper
from source import get_input


def main():
    helper = Helper()
    sink(helper.pass_through(get_input()))
