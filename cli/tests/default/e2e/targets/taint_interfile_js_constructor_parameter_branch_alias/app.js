import { Source } from "./source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const primary = new Source();
const fallback = new Source();
const selected = condition() ? primary : fallback;
new App(selected).run();
