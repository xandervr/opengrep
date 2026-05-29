import { ConstantFactorySource } from "./factory_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const SOURCE_KEY = "source";

function createServices() {
  return {
    [SOURCE_KEY]: new ConstantFactorySource(),
  };
}

const services = createServices();
new App(services[SOURCE_KEY]).run();
