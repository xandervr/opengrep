import { BindAsValueSource } from "./bind_as_value_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.bind("source").asValue(new BindAsValueSource());

new App(container.get("source")).run();
