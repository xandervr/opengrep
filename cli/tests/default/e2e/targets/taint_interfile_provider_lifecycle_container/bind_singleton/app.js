import { BindSingletonSource } from "./bind_singleton_source";

class BindSingletonApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.bind("source").to(BindSingletonSource).inSingletonScope();

new BindSingletonApp(container.get("source")).run();
