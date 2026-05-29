import { FactorySource } from "./factory_source";

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
    ["source"]: new FactorySource(),
  };
}

const services = createServices();
new App(services["source"]).run();
