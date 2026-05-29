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

const sourceFactory = factories.source;

const services = {
  source: sourceFactory(),
};

new App(services.source).run();
