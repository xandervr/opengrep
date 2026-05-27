import { Source } from "./source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const services = {
  source: new Source(),
  logger: {},
};

const { logger, ...runtimeServices } = services;

new App(runtimeServices.source).run();
