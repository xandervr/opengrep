import { Source } from "./source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const factories = {
  source: () => new Source(),
};

const services = {
  source: factories.source(),
};

new App(services.source).run();
