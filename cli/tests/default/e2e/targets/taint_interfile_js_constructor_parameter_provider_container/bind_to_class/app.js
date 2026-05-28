import { BindToClassSource } from "./bind_to_class_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.bind("source").to(BindToClassSource);

new App(container.get("source")).run();
