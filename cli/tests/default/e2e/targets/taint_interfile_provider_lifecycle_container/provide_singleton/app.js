import { ProvideSingletonSource } from "./provide_singleton_source";

class ProvideSingletonApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.provide("source").useClass(ProvideSingletonSource).singleton();

new ProvideSingletonApp(container.resolve("source")).run();
