<?php
require_once "higher.php";
sink(apply_callback(function($value) { return $value; }));
