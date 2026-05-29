class App {
  public static void Main() {
    sink(Helpers.PassThrough(Source.GetInput()));
  }
  public static void sink(string value) {}
}
