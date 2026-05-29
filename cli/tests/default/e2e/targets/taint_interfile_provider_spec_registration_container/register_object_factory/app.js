import { RegisterObjectFactorySource } from "./register_object_factory_source";

class RegisterObjectFactoryApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.register("source", {
  useFactory: () => new RegisterObjectFactorySource(),
});

new RegisterObjectFactoryApp(container.resolve("source")).run();
