import { ProvideUseFactorySource } from "./provide_use_factory_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.provide("source").useFactory(() => {
  return new ProvideUseFactorySource();
});

new App(container.get("source")).run();
