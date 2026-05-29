import { PropertySource } from "./property_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

function createServices() {
  return {
    source: new PropertySource(),
  };
}

const registry = { createServices };
const { source } = registry.createServices();
new App(source).run();
