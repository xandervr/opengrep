import helpers
import source


def main():
    sink(helpers.pass_through(source.get_input()))


main()
