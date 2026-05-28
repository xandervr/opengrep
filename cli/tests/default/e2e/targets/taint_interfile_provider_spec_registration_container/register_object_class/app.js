import { RegisterObjectClassSource } from "./register_object_class_source";

class RegisterObjectClassApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.register("source", { useClass: RegisterObjectClassSource });

new RegisterObjectClassApp(container.get("source")).run();
