import { FieldMetadataSource } from "./source";

function Injectable(): ClassDecorator {
  return () => {};
}

@Injectable()
class FieldMetadataApp {
  private source;

  constructor(source: FieldMetadataSource) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

new FieldMetadataApp().run();
