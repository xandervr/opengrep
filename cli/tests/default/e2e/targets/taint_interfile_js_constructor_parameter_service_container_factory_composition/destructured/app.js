import { DestructuredSource } from "./destructured_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

function buildServices() {
  return {
    source: new DestructuredSource(),
  };
}

function createServices() {
  return buildServices();
}

const { source } = createServices();
new App(source).run();
