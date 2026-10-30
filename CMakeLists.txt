cmake_minimum_required(VERSION 3.24)
project(MapCatHealthIcons LANGUAGES C)

add_library(MapCatHealthIcons SHARED
  src/MapCatHealthIcons.c
)

target_compile_features(MapCatHealthIcons PRIVATE c_std_11)

target_compile_definitions(MapCatHealthIcons PRIVATE
  WIN32_LEAN_AND_MEAN
  NOMINMAX
)

set_target_properties(MapCatHealthIcons PROPERTIES
  OUTPUT_NAME "MapCatHealthIcons"
)