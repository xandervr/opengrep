import { getInput } from "./source";
import { passThrough } from "./util";
import { unrelated } from "./unrelated";

function main() {
  const data = getInput();
  unrelated("safe");
  sink(passThrough(data));
}

main();
