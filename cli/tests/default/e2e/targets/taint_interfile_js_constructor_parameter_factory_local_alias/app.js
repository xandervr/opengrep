import { Source } from "./source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

function createSource() {
  const helper = new Source();
  return helper;
}

const selected = createSource();
new App(selected).run();
