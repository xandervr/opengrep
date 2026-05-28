import { BindAsClassSource } from "./bind_as_class_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.bind("source").asClass(BindAsClassSource);

new App(container.get("source")).run();
