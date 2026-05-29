import { DynamicMapSource } from "./map_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const sourceToken = selectServiceKey();
const services = new Map();
services.set(sourceToken, new DynamicMapSource());

new App(services.get(sourceToken)).run();
