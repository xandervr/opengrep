import { DirectMetadataSource } from "./source";

function Injectable(): ClassDecorator {
  return () => {};
}

@Injectable()
class DirectMetadataApp {
  constructor(source: DirectMetadataSource) {
    sink(source.getInput());
  }
}

new DirectMetadataApp();
