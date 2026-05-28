import { BindToConstantSource } from "./bind_to_constant_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.bind("source").toConstantValue(new BindToConstantSource());

new App(container.get("source")).run();
