import { BindGetSource } from "./bind_get_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.bind("source", new BindGetSource());

new App(container.get("source")).run();
