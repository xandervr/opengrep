import { Source } from "./source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const createSource = () => new Source();
const helper = createSource();
new App(helper).run();
