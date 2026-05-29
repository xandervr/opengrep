import { RegisterSingletonSource } from "./register_singleton_source";

class RegisterSingletonApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.register({
  source: asClass(RegisterSingletonSource).singleton(),
});

new RegisterSingletonApp(container.resolve("source")).run();
