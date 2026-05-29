import { getInput } from "./source";
import { passThrough } from "./helpers";
sink(passThrough(getInput()));
