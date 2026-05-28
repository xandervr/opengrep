import { DynamicProviderSource } from "./provider_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const sourceToken = selectServiceKey();
const services = {};
services.bind(sourceToken).to(DynamicProviderSource);

new App(services.get(sourceToken)).run();
