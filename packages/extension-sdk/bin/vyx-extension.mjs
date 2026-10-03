#!/usr/bin/env node
// Keep the executable present during npm ci, before the workspace compiles dist.
import '../dist/cli.js';
