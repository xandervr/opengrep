class AppSink {
  void run() {
    HigherSink.apply(value -> sink(value));
  }
}
