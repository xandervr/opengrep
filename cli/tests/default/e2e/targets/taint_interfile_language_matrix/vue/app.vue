<template><div /></template>
<script>
import { getInput } from "./source.vue";
import { passThrough } from "./helpers.vue";
sink(passThrough(getInput()));
</script>
