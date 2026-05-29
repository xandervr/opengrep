import { BindAsFunctionSource } from "./bind_as_function_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.bind("source").asFunction(() => {
  return new BindAsFunctionSource();
});

new App(container.get("source")).run();
