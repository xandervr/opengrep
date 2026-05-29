import { RegisterFactorySource } from "./register_factory_source";

class RegisterFactoryApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.register("source", asFunction(() => new RegisterFactorySource()));

new RegisterFactoryApp(container.resolve("source")).run();
