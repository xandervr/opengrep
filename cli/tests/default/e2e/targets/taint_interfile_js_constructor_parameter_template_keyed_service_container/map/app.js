import { MapTemplateSource } from "./map_template_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const SOURCE_KEY = "source";
const services = new Map();
services.set(`${SOURCE_KEY}`, new MapTemplateSource());

new App(services.get(`${SOURCE_KEY}`)).run();
