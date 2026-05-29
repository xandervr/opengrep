import { GetAsyncSource } from "./get_async_source";

class GetAsyncApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.bind("source").toDynamicValue(async () => {
  return new GetAsyncSource();
});

async function main() {
  new GetAsyncApp(await container.getAsync("source")).run();
}

main();
