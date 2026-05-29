from helpers import pass_through, sanitize


def main():
    sink(sanitize(source()))
    sink(pass_through(source()))
