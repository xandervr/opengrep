import { Source } from "./source";

class App {
  constructor() {
    this.source = new Source();
  }

  run() {
    sink(this.source.getInput());
  }
}

new App().run();
