import { DirectSource } from "./direct_source";

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
    source: new DirectSource(),
  };
}

const services = createServices();
new App(services.source).run();
