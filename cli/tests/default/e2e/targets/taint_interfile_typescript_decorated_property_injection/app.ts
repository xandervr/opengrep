import { Source } from "./source";

function Injectable(): ClassDecorator {
  return (target) => target;
}

function Inject(_key: string): PropertyDecorator {
  return (_target, _propertyKey) => {};
}

const container = {};
container.bind("source").to(Source);

@Injectable()
class App {
  @Inject("source")
  source;

  run() {
    sink(this.source.getInput());
  }
}

new App().run();
