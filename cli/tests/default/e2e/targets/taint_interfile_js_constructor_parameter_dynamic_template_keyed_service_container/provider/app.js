import { DynamicTemplateProviderSource } from "./provider_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const sourceSuffix = selectServiceSuffix();
const services = {};
services.bind(`sou${sourceSuffix}`).to(DynamicTemplateProviderSource);

new App(services.get(`sou${sourceSuffix}`)).run();
