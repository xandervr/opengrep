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

const factory = getFactory();
const helper = factory();
new App(helper).run();
