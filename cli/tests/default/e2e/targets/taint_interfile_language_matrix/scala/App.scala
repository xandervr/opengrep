object App {
  def main(args: Array[String]): Unit = { sink(Helpers.passThrough(Source.getInput())) }
  def sink(value: String): Unit = {}
}
