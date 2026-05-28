import { UseValueSource } from "./use_value_source";

class UseValueApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.register([{ token: "source", useValue: new UseValueSource() }]);

new UseValueApp(container.lookup("source")).run();
