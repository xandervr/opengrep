import { ProvideUseClassSource } from "./provide_use_class_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.provide("source").useClass(ProvideUseClassSource);

new App(container.get("source")).run();
