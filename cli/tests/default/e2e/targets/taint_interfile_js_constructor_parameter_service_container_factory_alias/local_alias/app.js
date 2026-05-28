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
  return {
    source: new LocalAliasSource(),
  };
}

const createRuntimeServices = createServices;
const services = createRuntimeServices();
new App(services.source).run();
