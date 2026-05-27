public class App {
  public static void run() {
    sink(Helpers.passThrough(Source.getInput()));
  }
  public static void sink(String value) {}
}
