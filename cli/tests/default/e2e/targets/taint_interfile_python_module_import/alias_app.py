import helpers as h
import source as s


def alias_main():
    sink(h.pass_through(s.get_input()))


alias_main()
