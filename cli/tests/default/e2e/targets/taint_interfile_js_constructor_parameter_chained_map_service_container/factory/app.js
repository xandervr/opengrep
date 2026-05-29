import { FactoryChainSource } from "./factory_chain_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

function createServices() {
  return new Map().set("source", new FactoryChainSource());
}

const services = createServices();
new App(services.get("source")).run();
