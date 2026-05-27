using System;

class HigherReturn {
  public static string Apply(Func<string, string> callback) {
    return callback.Invoke(SourceReturn.GetInput());
  }
}
