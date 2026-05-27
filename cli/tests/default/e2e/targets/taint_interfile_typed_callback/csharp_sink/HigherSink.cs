using System;

class HigherSink {
  public static void Apply(Action<string> callback) {
    callback.Invoke(SourceSink.GetInput());
  }
}
