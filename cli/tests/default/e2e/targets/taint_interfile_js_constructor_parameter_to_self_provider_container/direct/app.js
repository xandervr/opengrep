import { ToSelfDirectSource } from "./source";

class ToSelfDirectApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.bind(ToSelfDirectSource).toSelf();

new ToSelfDirectApp(container.get(ToSelfDirectSource)).run();
