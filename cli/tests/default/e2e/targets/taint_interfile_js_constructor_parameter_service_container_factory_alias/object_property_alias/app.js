import { ObjectPropertyAliasSource } from "./object_property_alias_source";

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
    source: new ObjectPropertyAliasSource(),
  };
}

const factories = {
  services: createServices,
};

const createRuntimeServices = factories.services;
const services = createRuntimeServices();
new App(services.source).run();
