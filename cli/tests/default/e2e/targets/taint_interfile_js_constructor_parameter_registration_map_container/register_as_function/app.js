import { RegisterAsFunctionSource } from "./register_as_function_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.register({
  source: asFunction(() => {
    return new RegisterAsFunctionSource();
  }),
});

new App(container.resolve("source")).run();
