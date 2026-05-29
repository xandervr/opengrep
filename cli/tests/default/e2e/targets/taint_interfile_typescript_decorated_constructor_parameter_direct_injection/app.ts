import { Source } from "./source";

function Injectable(): ClassDecorator {
  return (target) => target;
}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

const container = {};
container.bind("source").to(Source);

@Injectable()
class App {
  constructor(@Inject("source") source) {
    sink(source.getInput());
  }
}

new App();
