import { Source } from "./source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

function createSource() {
  return new Source();
}

const factories = {
  source: createSource,
};

const services = {
  source: factories.source(),
};

new App(services.source).run();
