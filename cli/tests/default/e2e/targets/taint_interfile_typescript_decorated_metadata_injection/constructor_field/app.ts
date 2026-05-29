import { ConstructorFieldSource } from "./source";

function Injectable(): ClassDecorator {
  return (target) => target;
}

function Inject(): ParameterDecorator {
  return () => {};
}

@Injectable()
class ConstructorFieldApp {
  private source;

  constructor(@Inject() source: ConstructorFieldSource) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

new ConstructorFieldApp().run();
