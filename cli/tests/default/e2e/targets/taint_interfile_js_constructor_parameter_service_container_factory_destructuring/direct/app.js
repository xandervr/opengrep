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

const { source } = createServices();
new App(source).run();
