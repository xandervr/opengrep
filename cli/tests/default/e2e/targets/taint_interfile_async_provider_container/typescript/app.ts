import { TsAsyncSource } from "./ts_async_source";

class TsAsyncApp {
  private source: TsAsyncSource;

  constructor(source: TsAsyncSource) {
    this.source = source;
  }

  async run() {
    sink(this.source.getInput());
  }
}

const container: any = {};
container.bind("source").toDynamicValue(async () => {
  return new TsAsyncSource();
});

async function main() {
  const helper = await container.getAsync("source");
  new TsAsyncApp(helper).run();
}

main();
