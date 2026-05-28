import { ObjectPropertySource } from "./object_property_source";

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
    source: new ObjectPropertySource(),
  };
}

const factories = {
  services: createServices,
};

const services = factories.services();
new App(services.source).run();
