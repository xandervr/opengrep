import { InlineSource } from "./inline_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const factories = {
  source: () => new InlineSource(),
};

const registry = {};
registry.source = factories.source;

const services = {
  source: registry.source(),
};

new App(services.source).run();
