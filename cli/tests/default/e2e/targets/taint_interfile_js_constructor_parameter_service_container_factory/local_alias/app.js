import { LocalAliasSource } from "./local_alias_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

function createServices() {
  const services = {
    source: new LocalAliasSource(),
  };
  return services;
}

const services = createServices();
new App(services.source).run();
