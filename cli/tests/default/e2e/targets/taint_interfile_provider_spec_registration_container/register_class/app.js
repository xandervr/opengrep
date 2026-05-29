import { RegisterClassSource } from "./register_class_source";

class RegisterClassApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.register("source", asClass(RegisterClassSource));

new RegisterClassApp(container.get("source")).run();
