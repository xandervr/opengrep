import { ProvideUseValueSource } from "./provide_use_value_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.provide("source").useValue(new ProvideUseValueSource());

new App(container.get("source")).run();
