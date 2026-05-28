import { FactoryMapSource } from "./factory_map_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

function createServices() {
  const services = new Map();
  services.set("source", new FactoryMapSource());
  return services;
}

const services = createServices();
new App(services.get("source")).run();
