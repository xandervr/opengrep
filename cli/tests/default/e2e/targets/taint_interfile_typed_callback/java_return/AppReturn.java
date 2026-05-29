class AppReturn {
  void run() {
    sink(HigherReturn.apply(value -> value));
  }
}
