import { TupleFactorySource } from "./tuple_factory_source";

class TupleFactoryApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.register([["source", asFunction(() => new TupleFactorySource())]]);

new TupleFactoryApp(container.resolve("source")).run();
