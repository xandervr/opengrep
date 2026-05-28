import { RegisterAsValueSource } from "./register_as_value_source";

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
  source: asValue(new RegisterAsValueSource()),
});

new App(container.resolve("source")).run();
