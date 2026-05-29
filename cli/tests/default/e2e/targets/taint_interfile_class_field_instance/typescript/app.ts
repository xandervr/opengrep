import { Source } from "./source";

class App {
  private source = new Source();

  run() {
    sink(this.source.getInput());
  }
}

new App().run();
