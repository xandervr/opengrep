import { ProvideUseExistingSource } from "./provide_use_existing_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.provide("source").useClass(ProvideUseExistingSource);
container.provide("alias").useExisting("source");

new App(container.resolve("alias")).run();
