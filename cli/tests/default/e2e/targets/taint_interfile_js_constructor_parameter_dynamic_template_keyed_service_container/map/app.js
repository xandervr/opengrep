import { DynamicTemplateMapSource } from "./map_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const sourceSuffix = selectServiceSuffix();
const services = new Map();
services.set(`sou${sourceSuffix}`, new DynamicTemplateMapSource());

new App(services.get(`sou${sourceSuffix}`)).run();
