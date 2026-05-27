class Base:
    def __init__(self):
        self.value = source()

    def get_input(self):
        return self.value


class Child(Base):
    pass
