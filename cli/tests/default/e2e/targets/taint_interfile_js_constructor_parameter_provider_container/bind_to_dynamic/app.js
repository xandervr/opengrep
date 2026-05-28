import { BindToDynamicSource } from "./bind_to_dynamic_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.bind("source").toDynamicValue(() => {
  return new BindToDynamicSource();
});

new App(container.get("source")).run();
