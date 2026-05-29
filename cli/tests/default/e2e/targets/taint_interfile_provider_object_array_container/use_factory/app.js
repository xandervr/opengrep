import { UseFactorySource } from "./use_factory_source";

class UseFactoryApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.register([{ name: "source", useFactory: () => new UseFactorySource() }]);

new UseFactoryApp(container.resolve("source")).run();
