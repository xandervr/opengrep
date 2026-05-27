import { getInput } from "./source";
import { clean } from "./helpers";

function main() {
  sink(clean(getInput()));
  sink(getInput());
}
