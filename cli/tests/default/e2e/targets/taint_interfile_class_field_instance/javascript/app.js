import { Source } from "./source";

class App {
  source = new Source();

  run() {
    sink(this.source.getInput());
  }
}

new App().run();
