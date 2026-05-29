import { TupleClassSource } from "./tuple_class_source";

class TupleClassApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.register([["source", asClass(TupleClassSource)]]);

new TupleClassApp(container.get("source")).run();
