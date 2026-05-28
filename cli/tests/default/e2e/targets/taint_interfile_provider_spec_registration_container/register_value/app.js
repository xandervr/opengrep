import { RegisterValueSource } from "./register_value_source";

class RegisterValueApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.register("source", asValue(new RegisterValueSource()));

new RegisterValueApp(container.lookup("source")).run();
