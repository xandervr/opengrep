import { RegisterResolveSource } from "./register_resolve_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.register("source", new RegisterResolveSource());

new App(container.resolve("source")).run();
