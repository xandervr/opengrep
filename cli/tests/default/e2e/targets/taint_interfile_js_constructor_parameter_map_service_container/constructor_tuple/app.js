import { ConstructorTupleMapSource } from "./constructor_tuple_map_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const services = new Map([["source", new ConstructorTupleMapSource()]]);

new App(services.get("source")).run();
