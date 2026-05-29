from pkg_a.source import data as tainted_data
from pkg_b.source import data as safe_data


def main():
    sink(tainted_data)
    sink(safe_data)
