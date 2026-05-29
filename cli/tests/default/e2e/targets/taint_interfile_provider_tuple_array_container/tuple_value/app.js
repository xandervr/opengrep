import { TupleValueSource } from "./tuple_value_source";

class TupleValueApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.register([["source", asValue(new TupleValueSource())]]);

new TupleValueApp(container.lookup("source")).run();
