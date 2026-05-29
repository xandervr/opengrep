import { Source } from "./source";

class App {
  constructor(private source: Source) {}

  run() {
    sink(this.source.getInput());
  }
}

new App(new Source()).run();
