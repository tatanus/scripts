#!/usr/bin/env bats

@test "bin directory exists" {
  [ -d "bin" ]
}

@test "docs directory exists" {
  [ -d "docs" ]
}

@test "can source common_core core.sh" {
  run bash -lc 'source lib/common_core/lib/core.sh'
  [ "$status" -eq 0 ]
}
