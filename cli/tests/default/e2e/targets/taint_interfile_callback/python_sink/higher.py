from source import source_sink


def apply_sink(callback):
    callback(source_sink())
