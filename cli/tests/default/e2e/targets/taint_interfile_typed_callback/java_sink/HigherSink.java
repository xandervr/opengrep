import java.util.function.Consumer;

class HigherSink {
  static void apply(Consumer<String> callback) {
    callback.accept(SourceSink.getInput());
  }
}
