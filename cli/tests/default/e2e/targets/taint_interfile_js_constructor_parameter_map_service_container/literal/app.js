import { LiteralMapSource } from "./literal_map_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const services = new Map();
services.set("source", new LiteralMapSource());

new App(services.get("source")).run();
