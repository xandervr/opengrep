import { ComputedFactorySource } from "./factory_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const SOURCE_KEY = "so" + "ur" + "ce";

function createServices() {
  return {
    [SOURCE_KEY]: new ComputedFactorySource(),
  };
}

const services = createServices();
new App(services[SOURCE_KEY]).run();
