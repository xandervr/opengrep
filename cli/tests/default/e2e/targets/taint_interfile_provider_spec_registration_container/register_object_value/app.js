import { RegisterObjectValueSource } from "./register_object_value_source";

class RegisterObjectValueApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.register("source", { useValue: new RegisterObjectValueSource() });

new RegisterObjectValueApp(container.lookup("source")).run();
