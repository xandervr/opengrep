import { NamedSource } from "./named_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

function createSource() {
  return new NamedSource();
}

const factories = {
  source: createSource,
};

const sourceFactory = factories.source;

const services = {
  source: sourceFactory(),
};

new App(services.source).run();
