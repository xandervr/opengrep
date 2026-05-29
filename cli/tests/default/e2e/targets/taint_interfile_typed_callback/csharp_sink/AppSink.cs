class AppSink {
  void Run() {
    HigherSink.Apply(value => sink(value));
  }
}
