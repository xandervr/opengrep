import { LocalAliasSource } from "./local_alias_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

function buildServices() {
  return {
    source: new LocalAliasSource(),
  };
}

function createServices() {
  const services = buildServices();
  return services;
}

const services = createServices();
new App(services.source).run();
