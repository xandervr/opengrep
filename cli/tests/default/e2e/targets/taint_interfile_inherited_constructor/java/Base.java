class Base {
  String value;

  Base() {
    this.value = source();
  }

  String getInput() {
    return this.value;
  }
}
