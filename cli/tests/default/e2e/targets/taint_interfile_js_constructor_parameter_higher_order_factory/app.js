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
  return new Source();
}

function getFactory() {
  return createSource;
}

const helper = getFactory()();
new App(helper).run();
