import { BindToServiceSource } from "./bind_to_service_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.bind("source").to(BindToServiceSource);
container.bind("alias").toService("source");

new App(container.get("alias")).run();
