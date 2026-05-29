import { UseClassSource } from "./use_class_source";

class UseClassApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.register([{ provide: "source", useClass: UseClassSource }]);

new UseClassApp(container.get("source")).run();
