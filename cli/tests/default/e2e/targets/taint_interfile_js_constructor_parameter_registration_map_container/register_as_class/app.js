import { RegisterAsClassSource } from "./register_as_class_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.register({
  source: asClass(RegisterAsClassSource),
});

new App(container.resolve("source")).run();
