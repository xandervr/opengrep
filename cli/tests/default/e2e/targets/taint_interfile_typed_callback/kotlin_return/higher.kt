fun applyReturn(callback: (String) -> String): String =
  callback(sourceReturn())
