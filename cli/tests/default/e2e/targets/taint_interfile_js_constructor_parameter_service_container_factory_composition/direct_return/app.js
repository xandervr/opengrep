import { DirectReturnSource } from "./direct_return_source";

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
    source: new DirectReturnSource(),
  };
}

function createServices() {
  return buildServices();
}

const services = createServices();
new App(services.source).run();
