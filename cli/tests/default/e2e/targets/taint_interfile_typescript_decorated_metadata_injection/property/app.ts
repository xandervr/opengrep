import { PropertySource } from "./source";

function Injectable(): ClassDecorator {
  return (target) => target;
}

function Inject(): PropertyDecorator {
  return () => {};
}

@Injectable()
class PropertyApp {
  @Inject()
  source: PropertySource;

  run() {
    sink(this.source.getInput());
  }
}

new PropertyApp().run();
