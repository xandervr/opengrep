import { ConstructorDirectSource } from "./source";

function Injectable(): ClassDecorator {
  return (target) => target;
}

function Inject(): ParameterDecorator {
  return () => {};
}

@Injectable()
class ConstructorDirectApp {
  constructor(@Inject() source: ConstructorDirectSource) {
    sink(source.getInput());
  }
}

new ConstructorDirectApp();
