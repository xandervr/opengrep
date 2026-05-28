import { ChainedContainerSource } from "./chained_container_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

new App(
  createContainer()
    .register("source", new ChainedContainerSource())
    .resolve("source")
).run();

function createContainer() {
  return {};
}
