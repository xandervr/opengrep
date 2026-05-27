import java.util.function.Function;

class HigherReturn {
  static String apply(Function<String, String> callback) {
    return callback.apply(SourceReturn.getInput());
  }
}
