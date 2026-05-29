import { Source } from "./source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const helper = new Source();
const selected = helper;
new App(selected).run();
